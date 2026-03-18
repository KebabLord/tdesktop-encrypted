/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "api/api_updates.h"

#include "api/api_authorizations.h"
#include "api/api_user_names.h"
#include "api/api_chat_participants.h"
#include "api/api_global_privacy.h"
#include "api/api_ringtones.h"
#include "api/api_text_entities.h"
#include "api/api_user_privacy.h"
#include "api/api_unread_things.h"
#include "api/api_transcribes.h"
#include "main/main_session.h"
#include "main/main_account.h"
#include "mtproto/mtp_instance.h"
#include "mtproto/mtproto_config.h"
#include "mtproto/mtproto_dc_options.h"
#include "mtproto/mtproto_dh_utils.h"
#include "mtproto/mtproto_auth_key.h"
#include "chat_helpers/stickers_dice_pack.h"
#include "data/business/data_shortcut_messages.h"
#include "data/components/credits.h"
#include "data/components/gift_auctions.h"
#include "data/components/promo_suggestions.h"
#include "data/components/scheduled_messages.h"
#include "data/components/top_peers.h"
#include "data/notify/data_notify_settings.h"
#include "data/stickers/data_stickers.h"
#include "data/data_saved_messages.h"
#include "data/data_saved_sublist.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "data/data_chat.h"
#include "data/data_changes.h"
#include "data/data_channel.h"
#include "data/data_chat_filters.h"
#include "data/data_cloud_themes.h"
#include "data/data_emoji_statuses.h"
#include "data/data_group_call.h"
#include "data/data_drafts.h"
#include "data/data_histories.h"
#include "data/data_folder.h"
#include "data/data_forum.h"
#include "data/data_forum_topic.h"
#include "data/data_send_action.h"
#include "data/data_stories.h"
#include "data/data_message_reactions.h"
#include "inline_bots/bot_attach_web_view.h"
#include "chat_helpers/emoji_interactions.h"
#include "lang/lang_cloud_manager.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/history_item_helpers.h"
#include "history/history_streamed_drafts.h"
#include "history/history_unread_things.h"
#include "core/application.h"
#include "storage/storage_account.h"
#include "storage/storage_facade.h"
#include "storage/storage_user_photos.h"
#include "storage/storage_shared_media.h"
#include "calls/calls_instance.h"
#include "base/unixtime.h"
#include "window/window_session_controller.h"
#include "window/window_controller.h"
#include "ui/boxes/confirm_box.h"
#include "apiwrap.h"
#include "ui/text/format_values.h" // Ui::FormatPhone

#include "data/secret/secret_chat_manager.h"
#include "data/secret/secret_chat_storage.h"
#include "data/secret/secret_chat_state.h"

// To save objects temporarily.
#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <optional>
#include <cstring>

// Openssl for sha1
#include "base/openssl_help.h"

// Temporary on-disk state for one-to-one secret chats.
// This is only the cryptographic/session state needed to decrypt incoming payloads.
#include <map>

struct SecretChatState {
	int64 chat_id = 0;              // encryptedChat.id
	uint64 access_hash = 0;         // encryptedChat.access_hash
	uint64 admin_id = 0;            // encryptedChat.admin_id
	uint64 participant_id = 0;      // encryptedChat.participant_id
	bool is_creator = false;        // true if we started the secret chat
	uint64 key_fingerprint = 0;     // low 64 bits of SHA1(auth_key)
	MTP::AuthKey::Data auth_key;    // 256-byte shared secret chat key
};

static std::map<uint64, SecretChatState> g_secretChats;

namespace {

constexpr auto kSecretChatsDir = "/home/owo/Github/tdesktop/tmp/secret_chats";

// Current implementation target: layer 73 secret chat messages.
// Official docs: decryptedMessageLayer was introduced in layer 17,
// current inner constructor we observe is decryptedMessage#91cc4674 (layer 73).
constexpr uint32 kSecretOuterLayerConstructor = 0x1be31789;      // decryptedMessageLayer
constexpr uint32 kSecretInnerMessageV73 = 0x91cc4674;            // decryptedMessage, layer 73
constexpr uint32 kSecretInnerServiceV17 = 0x73164160;            // decryptedMessageService
constexpr uint32 kTlVectorConstructor = 0x1cb5c415;              // vector
constexpr int kMinSecretRandomBytes = 15;                        // required by docs
constexpr int kMinMtproto2Padding = 12;                          // required by docs
constexpr int kMaxMtproto2Padding = 1024;                        // required by docs

// Build the path used to persist one secret chat state.
[[nodiscard]] QString SecretChatStatePath(int64 chatId) {
	return QString("%1/%2.json").arg(kSecretChatsDir).arg(chatId);
}

// Convert auth_key bytes to hex for JSON persistence.
[[nodiscard]] QString AuthKeyToHex(const MTP::AuthKey::Data &authKey) {
	const auto raw = QByteArray(
		reinterpret_cast<const char*>(authKey.data()),
		int(authKey.size()));
	return QString::fromLatin1(raw.toHex());
}

// Restore auth_key bytes from persisted hex.
[[nodiscard]] bool AuthKeyFromHex(
		const QString &hex,
		MTP::AuthKey::Data &out) {
	const auto raw = QByteArray::fromHex(hex.toLatin1());
	if (raw.size() != int(MTP::AuthKey::kSize)) {
		return false;
	}
	std::memcpy(out.data(), raw.constData(), size_t(raw.size()));
	return true;
}

// Persist current secret chat state to disk so later runs can decrypt messages.
[[nodiscard]] bool SaveSecretChatState(const SecretChatState &state) {
	QDir dir;
	if (!dir.mkpath(kSecretChatsDir)) {
		LOG(("1337 SecretChat: failed to create state dir %1").arg(kSecretChatsDir));
		return false;
	}

	const auto object = QJsonObject{
		{ "chat_id", QString::number(state.chat_id) },
		{ "access_hash", QString::number(static_cast<qulonglong>(state.access_hash)) },
		{ "admin_id", QString::number(static_cast<qulonglong>(state.admin_id)) },
		{ "participant_id", QString::number(static_cast<qulonglong>(state.participant_id)) },
		{ "is_creator", QString::number(static_cast<qulonglong>(state.is_creator)) },
		{ "key_fingerprint", QString::number(static_cast<qulonglong>(state.key_fingerprint)) },
		{ "auth_key_hex", AuthKeyToHex(state.auth_key) },
	};

	auto file = QSaveFile(SecretChatStatePath(state.chat_id));
	if (!file.open(QIODevice::WriteOnly)) {
		LOG(("1337 SecretChat: failed to open state file %1")
			.arg(SecretChatStatePath(state.chat_id)));
		return false;
	}
	if (file.write(QJsonDocument(object).toJson(QJsonDocument::Indented)) < 0) {
		LOG(("1337 SecretChat: failed to write state file %1")
			.arg(SecretChatStatePath(state.chat_id)));
		return false;
	}
	if (!file.commit()) {
		LOG(("1337 SecretChat: failed to commit state file %1")
			.arg(SecretChatStatePath(state.chat_id)));
		return false;
	}

	LOG(("1337 SecretChat: saved state to %1")
		.arg(SecretChatStatePath(state.chat_id)));
	return true;
}

// Load previously saved secret chat state for decrypting incoming updates.
[[nodiscard]] std::optional<SecretChatState> LoadSecretChatState(int64 chatId) {
	auto file = QFile(SecretChatStatePath(chatId));
	if (!file.exists()) {
		LOG(("1337 SecretChat: state file does not exist for chat_id=%1 path=%2")
			.arg(chatId)
			.arg(SecretChatStatePath(chatId)));
		return std::nullopt;
	}
	if (!file.open(QIODevice::ReadOnly)) {
		LOG(("1337 SecretChat: failed to open state file %1")
			.arg(SecretChatStatePath(chatId)));
		return std::nullopt;
	}

	const auto doc = QJsonDocument::fromJson(file.readAll());
	if (!doc.isObject()) {
		LOG(("1337 SecretChat: invalid JSON in state file %1")
			.arg(SecretChatStatePath(chatId)));
		return std::nullopt;
	}

	const auto object = doc.object();
	SecretChatState state;

	bool ok = false;

	state.chat_id = object.value("chat_id").toString().toLongLong(&ok);
	if (!ok) {
		LOG(("1337 SecretChat: invalid chat_id in state file %1")
			.arg(SecretChatStatePath(chatId)));
		return std::nullopt;
	}

	state.access_hash = object.value("access_hash").toString().toULongLong(&ok);
	if (!ok) {
		LOG(("1337 SecretChat: invalid access_hash in state file %1")
			.arg(SecretChatStatePath(chatId)));
		return std::nullopt;
	}

	state.admin_id = object.value("admin_id").toString().toULongLong(&ok);
	if (!ok) {
		LOG(("1337 SecretChat: invalid admin_id in state file %1")
			.arg(SecretChatStatePath(chatId)));
		return std::nullopt;
	}

	state.participant_id = object.value("participant_id").toString().toULongLong(&ok);
	if (!ok) {
		LOG(("1337 SecretChat: invalid participant_id in state file %1")
			.arg(SecretChatStatePath(chatId)));
		return std::nullopt;
	}

	state.is_creator = object.value("is_creator").toString().toShort(&ok);
	if (!ok) {
		LOG(("1337 SecretChat: invalid is_creator in state file %1")
			.arg(SecretChatStatePath(chatId)));
		return std::nullopt;
	}

	state.key_fingerprint = object.value("key_fingerprint").toString().toULongLong(&ok);
	if (!ok) {
		LOG(("1337 SecretChat: invalid key_fingerprint in state file %1")
			.arg(SecretChatStatePath(chatId)));
		return std::nullopt;
	}

	if (!AuthKeyFromHex(object.value("auth_key_hex").toString(), state.auth_key)) {
		LOG(("1337 SecretChat: invalid auth_key_hex in state file %1")
			.arg(SecretChatStatePath(chatId)));
		return std::nullopt;
	}

	LOG(("1337 SecretChat: loaded state for chat_id=%1 key_fingerprint=%2 is_creator=%3")
		.arg(state.chat_id)
		.arg(QString::number(static_cast<qulonglong>(state.key_fingerprint)))
		.arg(state.is_creator ? 1 : 0));
	return state;
}

// Small formatting helpers for logs.
[[nodiscard]] QString BytesToHex(const QByteArray &data, int maxBytes = -1) {
	const auto slice = (maxBytes >= 0) ? data.left(maxBytes) : data;
	return QString::fromLatin1(slice.toHex());
}

[[nodiscard]] QString FormatUint32Hex(uint32 value) {
	return QString("0x%1").arg(value, 8, 16, QLatin1Char('0'));
}

[[nodiscard]] QString FormatUint64(uint64 value) {
	return QString::number(static_cast<qulonglong>(value));
}

[[nodiscard]] uint32 ReadLE32(const char *data) {
	uint32 value = 0;
	std::memcpy(&value, data, sizeof(value));
	return value;
}

[[nodiscard]] uint64 ReadLE64(const char *data) {
	uint64 value = 0;
	std::memcpy(&value, data, sizeof(value));
	return value;
}

// A tiny TL reader over an already decrypted payload body.
// It reads from [offset, limit) and advances only on success.
struct SecretTlReader {
	const QByteArray &data;
	int offset = 0;
	int limit = 0;

	[[nodiscard]] bool CanRead(int bytes) const {
		return (bytes >= 0) && (offset >= 0) && (offset + bytes <= limit);
	}

	[[nodiscard]] std::optional<uint32> ReadUInt32() {
		if (!CanRead(4)) {
			return std::nullopt;
		}
		const auto value = ReadLE32(data.constData() + offset);
		offset += 4;
		return value;
	}

	[[nodiscard]] std::optional<int32> ReadInt32() {
		const auto value = ReadUInt32();
		if (!value.has_value()) {
			return std::nullopt;
		}
		return static_cast<int32>(*value);
	}

	[[nodiscard]] std::optional<uint64> ReadUInt64() {
		if (!CanRead(8)) {
			return std::nullopt;
		}
		const auto value = ReadLE64(data.constData() + offset);
		offset += 8;
		return value;
	}

	[[nodiscard]] std::optional<QByteArray> ReadTLBytes() {
		if (!CanRead(1)) {
			return std::nullopt;
		}

		const auto first = static_cast<uchar>(data[offset]);
		int length = 0;
		int headerSize = 0;

		if (first < 254) {
			length = first;
			headerSize = 1;
		} else {
			if (!CanRead(4)) {
				return std::nullopt;
			}
			length = static_cast<uchar>(data[offset + 1])
				| (static_cast<uchar>(data[offset + 2]) << 8)
				| (static_cast<uchar>(data[offset + 3]) << 16);
			headerSize = 4;
		}

		const auto padded = ((headerSize + length) + 3) & ~3;
		if (!CanRead(padded)) {
			return std::nullopt;
		}

		const auto result = data.mid(offset + headerSize, length);
		offset += padded;
		return result;
	}

	[[nodiscard]] std::optional<QString> ReadTLString() {
		const auto bytes = ReadTLBytes();
		if (!bytes.has_value()) {
			return std::nullopt;
		}
		return QString::fromUtf8(bytes->constData(), bytes->size());
	}
};

// Human-readable names for constructors we already observed.
[[nodiscard]] QString SecretMessageEntityName(uint32 constructor) {
	switch (constructor) {
	case 0xbd610bc9: return QStringLiteral("bold");
	case 0x826f8b60: return QStringLiteral("italic");
	case 0x28a20571: return QStringLiteral("code");
	case 0x73924be0: return QStringLiteral("pre");
	case 0x32ca960f: return QStringLiteral("spoiler");
	case 0x9c4e7e8b: return QStringLiteral("strike");
	case 0xfa04579d: return QStringLiteral("underline");
	case 0x6ed02538: return QStringLiteral("blockquote");
	default: return QString("unknown(%1)").arg(FormatUint32Hex(constructor));
	}
}

// Best-effort names for secret media constructors we care about first.
[[nodiscard]] QString SecretMediaConstructorName(uint32 constructor) {
	switch (constructor) {
	case 0x089f5c4a: return QStringLiteral("decryptedMessageMediaEmpty");
	case 0xf1fa8d78: return QStringLiteral("decryptedMessageMediaPhoto");
	case 0x970c8c0e: return QStringLiteral("decryptedMessageMediaVideo");
	case 0x7afe8ae2: return QStringLiteral("decryptedMessageMediaDocument");
	case 0x6abd9782: return QStringLiteral("decryptedMessageMediaDocument(layer143+)");
	case 0x57e0a9cb: return QStringLiteral("decryptedMessageMediaAudio");
	case 0xfa95b0dd: return QStringLiteral("decryptedMessageMediaExternalDocument");
	case 0x8a0df56f: return QStringLiteral("decryptedMessageMediaVenue");
	case 0xe50511d8: return QStringLiteral("decryptedMessageMediaWebPage");
	default: return QString("unknown(%1)").arg(FormatUint32Hex(constructor));
	}
}

// Parse and log a Vector<MessageEntity> at the current reader position.
bool ParseSecretMessageEntities(
		int64 chatId,
		const char *tag,
		SecretTlReader &reader,
		const QString &messageText) {
	const auto vectorCtor = reader.ReadUInt32();
	const auto count = reader.ReadInt32();
	if (!vectorCtor.has_value() || !count.has_value()) {
		LOG(("1335 SecretChat: %1 entities header truncated chat_id=%2 offset=%3 limit=%4")
			.arg(QString::fromLatin1(tag))
			.arg(chatId)
			.arg(reader.offset)
			.arg(reader.limit));
		return false;
	}
	if (*vectorCtor != kTlVectorConstructor || *count < 0) {
		LOG(("1335 SecretChat: %1 invalid entities vector chat_id=%2 ctor=%3 count=%4")
			.arg(QString::fromLatin1(tag))
			.arg(chatId)
			.arg(FormatUint32Hex(*vectorCtor))
			.arg(*count));
		return false;
	}

	LOG(("1335 SecretChat: %1 entities chat_id=%2 count=%3")
		.arg(QString::fromLatin1(tag))
		.arg(chatId)
		.arg(*count));

	for (int i = 0; i != *count; ++i) {
		const auto entityCtor = reader.ReadUInt32();
		const auto entityOffset = reader.ReadInt32();
		const auto entityLength = reader.ReadInt32();
		if (!entityCtor.has_value()
			|| !entityOffset.has_value()
			|| !entityLength.has_value()) {
			LOG(("1335 SecretChat: %1 entity truncated chat_id=%2 index=%3 offset=%4 limit=%5")
				.arg(QString::fromLatin1(tag))
				.arg(chatId)
				.arg(i)
				.arg(reader.offset)
				.arg(reader.limit));
			return false;
		}

		QString entityText;
		if ((*entityOffset >= 0)
			&& (*entityLength >= 0)
			&& (*entityOffset + *entityLength <= messageText.size())) {
			entityText = messageText.mid(*entityOffset, *entityLength);
		}

		LOG(("1335 SecretChat: %1 entity chat_id=%2 index=%3 type=%4 offset=%5 length=%6 text=%7")
			.arg(QString::fromLatin1(tag))
			.arg(chatId)
			.arg(i)
			.arg(SecretMessageEntityName(*entityCtor))
			.arg(*entityOffset)
			.arg(*entityLength)
			.arg(entityText));
	}

	return true;
}

// Decrypt an incoming MTProto 2.0 secret chat payload and validate msg_key.
// On success, returns the full decrypted block: [length:int32][body][padding].
[[nodiscard]] std::optional<QByteArray> DecryptSecretChatPayloadMtproto2(
		const SecretChatState &state,
		const QByteArray &payload) {
	// External secret-chat envelope:
	// [key_fingerprint:8][msg_key:16][encrypted_data:N]
	if (payload.size() < 24) {
		LOG(("1335 SecretChat: payload too short for decryption size=%1")
			.arg(payload.size()));
		return std::nullopt;
	}

	const auto encryptedSize = payload.size() - 24;
	if ((encryptedSize <= 0) || (encryptedSize % 16 != 0)) {
		LOG(("1335 SecretChat: encrypted payload size is invalid size=%1")
			.arg(encryptedSize));
		return std::nullopt;
	}

	MTPint128 msgKey;
	std::memcpy(&msgKey, payload.constData() + 8, sizeof(msgKey));

	MTPint256 aesKey, aesIV;

	// MTProto 2.0 secret chats:
	// x = 0 for messages from the originator, x = 8 for the opposite direction.
	// We are decrypting incoming messages, so x depends on whether *we* are creator.
	const int x = state.is_creator ? 8 : 0;

	{
		bytes::array<32> sha256_a, sha256_b;

		bytes::array<16 + 36> data_a;
		std::memcpy(data_a.data(), &msgKey, 16);
		std::memcpy(
			data_a.data() + 16,
			reinterpret_cast<const uchar*>(state.auth_key.data()) + x,
			36);
		openssl::Sha256To(sha256_a, data_a);

		bytes::array<36 + 16> data_b;
		std::memcpy(
			data_b.data(),
			reinterpret_cast<const uchar*>(state.auth_key.data()) + 40 + x,
			36);
		std::memcpy(data_b.data() + 36, &msgKey, 16);
		openssl::Sha256To(sha256_b, data_b);

		auto key = reinterpret_cast<uchar*>(&aesKey);
		auto iv = reinterpret_cast<uchar*>(&aesIV);

		std::memcpy(key, sha256_a.data(), 8);
		std::memcpy(key + 8, sha256_b.data() + 8, 16);
		std::memcpy(key + 24, sha256_a.data() + 24, 8);

		std::memcpy(iv, sha256_b.data(), 8);
		std::memcpy(iv + 8, sha256_a.data() + 8, 16);
		std::memcpy(iv + 24, sha256_b.data() + 24, 8);
	}

	auto decrypted = QByteArray(encryptedSize, Qt::Uninitialized);
	MTP::aesIgeDecryptRaw(
		payload.constData() + 24,
		decrypted.data(),
		encryptedSize,
		&aesKey,
		&aesIV);

	// Verify msg_key = SHA256(auth_key[88+x:120+x] + plaintext_with_length_and_padding)[8:24].
	std::array<uchar, 32> sha256Buffer = { { 0 } };
	SHA256_CTX msgKeyLargeContext;
	SHA256_Init(&msgKeyLargeContext);
	SHA256_Update(
		&msgKeyLargeContext,
		reinterpret_cast<const uchar*>(state.auth_key.data()) + 88 + x,
		32);
	SHA256_Update(
		&msgKeyLargeContext,
		decrypted.constData(),
		size_t(encryptedSize));
	SHA256_Final(sha256Buffer.data(), &msgKeyLargeContext);

	constexpr auto kMsgKeyShift = 8U;
	if (std::memcmp(&msgKey, sha256Buffer.data() + kMsgKeyShift, sizeof(msgKey)) != 0) {
		LOG(("1335 SecretChat: MTProto2 msg_key verification failed x=%1")
			.arg(x));
		return std::nullopt;
	}

	// Validate [length:int32][body][padding] shape after successful decryption.
	if (decrypted.size() < 4) {
		LOG(("1335 SecretChat: decrypted payload too small after verify size=%1")
			.arg(decrypted.size()));
		return std::nullopt;
	}

	const auto bodyLength = int(ReadLE32(decrypted.constData()));
	const auto usedBytes = 4 + bodyLength;
	if (bodyLength < 0 || usedBytes > decrypted.size()) {
		LOG(("1335 SecretChat: invalid decrypted body length body_length=%1 decrypted_size=%2")
			.arg(bodyLength)
			.arg(decrypted.size()));
		return std::nullopt;
	}

	const auto paddingBytes = decrypted.size() - usedBytes;
	if (paddingBytes < kMinMtproto2Padding || paddingBytes > kMaxMtproto2Padding) {
		LOG(("1335 SecretChat: invalid MTProto2 padding body_length=%1 padding=%2 decrypted_size=%3")
			.arg(bodyLength)
			.arg(paddingBytes)
			.arg(decrypted.size()));
		return std::nullopt;
	}

	LOG(("1335 SecretChat: MTProto2 msg_key verification passed x=%1 body_length=%2 padding=%3")
		.arg(x)
		.arg(bodyLength)
		.arg(paddingBytes));

	return decrypted;
}

// Parse the decrypted secret-chat plaintext according to the official E2E TL schema.
// Expected top-level layout: [length:int32][decryptedMessageLayer][padding].
void ParseDecryptedSecretChatPayload(
		int64 chatId,
		const QByteArray &decrypted,
		const char *tag) {
	LOG(("1335 SecretChat: %1 decrypted payload chat_id=%2 size=%3 hex=%4")
		.arg(QString::fromLatin1(tag))
		.arg(chatId)
		.arg(decrypted.size())
		.arg(BytesToHex(decrypted, 256)));

	if (decrypted.size() < 4) {
		LOG(("1335 SecretChat: %1 decrypted payload too small chat_id=%2 size=%3")
			.arg(QString::fromLatin1(tag))
			.arg(chatId)
			.arg(decrypted.size()));
		return;
	}

	const auto bodyLength = int(ReadLE32(decrypted.constData()));
	const auto bodyLimit = 4 + bodyLength;
	if (bodyLength < 0 || bodyLimit > decrypted.size()) {
		LOG(("1335 SecretChat: %1 invalid body_length chat_id=%2 body_length=%3 decrypted_size=%4")
			.arg(QString::fromLatin1(tag))
			.arg(chatId)
			.arg(bodyLength)
			.arg(decrypted.size()));
		return;
	}

	SecretTlReader reader{ decrypted, 4, bodyLimit };

	// Outer wrapper must be decryptedMessageLayer#1be31789 at modern layers.
	const auto outerConstructor = reader.ReadUInt32();
	if (!outerConstructor.has_value()) {
		LOG(("1335 SecretChat: %1 failed to read outer constructor chat_id=%2")
			.arg(QString::fromLatin1(tag))
			.arg(chatId));
		return;
	}
	if (*outerConstructor != kSecretOuterLayerConstructor) {
		LOG(("1335 SecretChat: %1 unexpected outer constructor chat_id=%2 constructor=%3")
			.arg(QString::fromLatin1(tag))
			.arg(chatId)
			.arg(FormatUint32Hex(*outerConstructor)));
		return;
	}

	const auto randomBytes = reader.ReadTLBytes();
	const auto layer = reader.ReadInt32();
	const auto inSeqNo = reader.ReadInt32();
	const auto outSeqNo = reader.ReadInt32();
	if (!randomBytes.has_value()
		|| !layer.has_value()
		|| !inSeqNo.has_value()
		|| !outSeqNo.has_value()) {
		LOG(("1335 SecretChat: %1 outer layer truncated chat_id=%2 offset=%3 limit=%4")
			.arg(QString::fromLatin1(tag))
			.arg(chatId)
			.arg(reader.offset)
			.arg(reader.limit));
		return;
	}
	if (randomBytes->size() < kMinSecretRandomBytes) {
		LOG(("1335 SecretChat: %1 random_bytes too short chat_id=%2 random_size=%3")
			.arg(QString::fromLatin1(tag))
			.arg(chatId)
			.arg(randomBytes->size()));
		return;
	}

	LOG(("1335 SecretChat: %1 outer chat_id=%2 body_length=%3 layer=%4 in_seq_no=%5 out_seq_no=%6 random_size=%7 random=%8")
		.arg(QString::fromLatin1(tag))
		.arg(chatId)
		.arg(bodyLength)
		.arg(*layer)
		.arg(*inSeqNo)
		.arg(*outSeqNo)
		.arg(randomBytes->size())
		.arg(BytesToHex(*randomBytes)));

	const auto innerConstructor = reader.ReadUInt32();
	if (!innerConstructor.has_value()) {
		LOG(("1335 SecretChat: %1 missing inner constructor chat_id=%2")
			.arg(QString::fromLatin1(tag))
			.arg(chatId));
		return;
	}

	LOG(("1335 SecretChat: %1 inner chat_id=%2 constructor=%3")
		.arg(QString::fromLatin1(tag))
		.arg(chatId)
		.arg(FormatUint32Hex(*innerConstructor)));

	switch (*innerConstructor) {
	case kSecretInnerMessageV73: {
		// decryptedMessage#91cc4674
		const auto flags = reader.ReadUInt32();
		const auto randomId = reader.ReadUInt64();
		const auto ttl = reader.ReadInt32();
		const auto messageText = reader.ReadTLString();

		if (!flags.has_value()
			|| !randomId.has_value()
			|| !ttl.has_value()
			|| !messageText.has_value()) {
			LOG(("1335 SecretChat: %1 decryptedMessage(v73) truncated chat_id=%2 offset=%3 limit=%4")
				.arg(QString::fromLatin1(tag))
				.arg(chatId)
				.arg(reader.offset)
				.arg(reader.limit));
			return;
		}

		LOG(("1335 SecretChat: %1 decryptedMessage chat_id=%2 flags=%3 no_webpage=%4 silent=%5 random_id=%6 ttl=%7 text=%8")
			.arg(QString::fromLatin1(tag))
			.arg(chatId)
			.arg(FormatUint32Hex(*flags))
			.arg((*flags & (1 << 1)) ? 1 : 0)
			.arg((*flags & (1 << 5)) ? 1 : 0)
			.arg(FormatUint64(*randomId))
			.arg(*ttl)
			.arg(*messageText));

		// flags.9?DecryptedMessageMedia
		if (*flags & (1 << 9)) {
			const auto mediaConstructor = reader.ReadUInt32();
			if (!mediaConstructor.has_value()) {
				LOG(("1335 SecretChat: %1 media constructor missing chat_id=%2 offset=%3 limit=%4")
					.arg(QString::fromLatin1(tag))
					.arg(chatId)
					.arg(reader.offset)
					.arg(reader.limit));
				return;
			}
			LOG(("1335 SecretChat: %1 media chat_id=%2 constructor=%3 name=%4 remaining=%5")
				.arg(QString::fromLatin1(tag))
				.arg(chatId)
				.arg(FormatUint32Hex(*mediaConstructor))
				.arg(SecretMediaConstructorName(*mediaConstructor))
				.arg(reader.limit - reader.offset));
			// For now we only identify the typed media constructor.
			// Actual media body parsing/decryption will be the next stage.
		} else {
			LOG(("1335 SecretChat: %1 media chat_id=%2 none")
				.arg(QString::fromLatin1(tag))
				.arg(chatId));
		}

		// flags.7?Vector<MessageEntity>
		if (*flags & (1 << 7)) {
			if (!ParseSecretMessageEntities(chatId, tag, reader, *messageText)) {
				return;
			}
		}

		// flags.11?string via_bot_name
		if (*flags & (1 << 11)) {
			const auto viaBotName = reader.ReadTLString();
			if (!viaBotName.has_value()) {
				LOG(("1335 SecretChat: %1 via_bot_name truncated chat_id=%2 offset=%3 limit=%4")
					.arg(QString::fromLatin1(tag))
					.arg(chatId)
					.arg(reader.offset)
					.arg(reader.limit));
				return;
			}
			LOG(("1335 SecretChat: %1 via_bot_name chat_id=%2 value=%3")
				.arg(QString::fromLatin1(tag))
				.arg(chatId)
				.arg(*viaBotName));
		}

		// flags.3?long reply_to_random_id
		if (*flags & (1 << 3)) {
			const auto replyToRandomId = reader.ReadUInt64();
			if (!replyToRandomId.has_value()) {
				LOG(("1335 SecretChat: %1 reply_to_random_id truncated chat_id=%2 offset=%3 limit=%4")
					.arg(QString::fromLatin1(tag))
					.arg(chatId)
					.arg(reader.offset)
					.arg(reader.limit));
				return;
			}
			LOG(("1335 SecretChat: %1 reply_to_random_id chat_id=%2 value=%3")
				.arg(QString::fromLatin1(tag))
				.arg(chatId)
				.arg(FormatUint64(*replyToRandomId)));
		}

		// flags.17?long grouped_id
		if (*flags & (1 << 17)) {
			const auto groupedId = reader.ReadUInt64();
			if (!groupedId.has_value()) {
				LOG(("1335 SecretChat: %1 grouped_id truncated chat_id=%2 offset=%3 limit=%4")
					.arg(QString::fromLatin1(tag))
					.arg(chatId)
					.arg(reader.offset)
					.arg(reader.limit));
				return;
			}
			LOG(("1335 SecretChat: %1 grouped_id chat_id=%2 value=%3")
				.arg(QString::fromLatin1(tag))
				.arg(chatId)
				.arg(FormatUint64(*groupedId)));
		}
	} break;

	case kSecretInnerServiceV17: {
		// decryptedMessageService#73164160
		const auto randomId = reader.ReadUInt64();
		const auto actionConstructor = reader.ReadUInt32();
		if (!randomId.has_value() || !actionConstructor.has_value()) {
			LOG(("1335 SecretChat: %1 decryptedMessageService truncated chat_id=%2 offset=%3 limit=%4")
				.arg(QString::fromLatin1(tag))
				.arg(chatId)
				.arg(reader.offset)
				.arg(reader.limit));
			return;
		}

		LOG(("1335 SecretChat: %1 decryptedMessageService chat_id=%2 random_id=%3 action_constructor=%4")
			.arg(QString::fromLatin1(tag))
			.arg(chatId)
			.arg(FormatUint64(*randomId))
			.arg(FormatUint32Hex(*actionConstructor)));
	} break;

	default:
		LOG(("1335 SecretChat: %1 unsupported inner constructor chat_id=%2 constructor=%3")
			.arg(QString::fromLatin1(tag))
			.arg(chatId)
			.arg(FormatUint32Hex(*innerConstructor)));
		break;
	}

	const auto paddingBytes = decrypted.size() - bodyLimit;
	LOG(("1335 SecretChat: %1 parsed chat_id=%2 body_bytes=%3 padding_bytes=%4 final_offset=%5")
		.arg(QString::fromLatin1(tag))
		.arg(chatId)
		.arg(bodyLimit)
		.arg(paddingBytes)
		.arg(reader.offset));
}

} // namespace


namespace Api {
namespace {

constexpr auto kChannelGetDifferenceLimit = 100;

// 1s wait after show channel history before sending getChannelDifference.
constexpr auto kWaitForChannelGetDifference = crl::time(1000);

// If nothing is received in 1 min we ping.
constexpr auto kNoUpdatesTimeout = 60 * 1000;

// If nothing is received in 1 min when was a sleepmode we ping.
constexpr auto kNoUpdatesAfterSleepTimeout = 60 * crl::time(1000);

enum class DataIsLoadedResult {
	NotLoaded = 0,
	FromNotLoaded = 1,
	MentionNotLoaded = 2,
	Ok = 3,
};

void ProcessScheduledMessageWithElapsedTime(
		not_null<Main::Session*> session,
		bool needToAdd,
		const MTPDmessage &data) {
	if (needToAdd && !data.is_from_scheduled()) {
		// If we still need to add a new message,
		// we should first check if this message is in
		// the list of scheduled messages.
		// This is necessary to correctly update the file reference.
		// Note that when a message is scheduled until online
		// while the recipient is already online, the server sends
		// an ordinary new message with skipped "from_scheduled" flag.
		session->scheduledMessages().checkEntitiesAndUpdate(data);
	}
}

bool IsForceLogoutNotification(const MTPDupdateServiceNotification &data) {
	return qs(data.vtype()).startsWith(u"AUTH_KEY_DROP_"_q);
}

bool HasForceLogoutNotification(const MTPUpdates &updates) {
	const auto checkUpdate = [](const MTPUpdate &update) {
		if (update.type() != mtpc_updateServiceNotification) {
			return false;
		}
		return IsForceLogoutNotification(
			update.c_updateServiceNotification());
	};
	const auto checkVector = [&](const MTPVector<MTPUpdate> &list) {
		for (const auto &update : list.v) {
			if (checkUpdate(update)) {
				return true;
			}
		}
		return false;
	};
	switch (updates.type()) {
	case mtpc_updates:
		return checkVector(updates.c_updates().vupdates());
	case mtpc_updatesCombined:
		return checkVector(updates.c_updatesCombined().vupdates());
	case mtpc_updateShort:
		return checkUpdate(updates.c_updateShort().vupdate());
	}
	return false;
}

} // namespace

Updates::Updates(not_null<Main::Session*> session)
: _session(session)
, _noUpdatesTimer([=] { sendPing(); })
, _onlineTimer([=] { updateOnline(); })
, _ptsWaiter(this)
, _byPtsTimer([=] { getDifferenceByPts(); })
, _bySeqTimer([=] { getDifference(); })
, _byMinChannelTimer([=] { getDifference(); })
, _failDifferenceTimer([=] { getDifferenceAfterFail(); })
, _idleFinishTimer([=] { checkIdleFinish(); }) {
	_ptsWaiter.setRequesting(true);

	session->account().mtpUpdates(
	) | rpl::on_next([=](const MTPUpdates &updates) {
		mtpUpdateReceived(updates);
	}, _lifetime);

	session->account().mtpNewSessionCreated(
	) | rpl::on_next([=] {
		mtpNewSessionCreated();
	}, _lifetime);

	api().request(MTPupdates_GetState(
	)).done([=](const MTPupdates_State &result) {
		stateDone(result);
	}).send();

	using namespace rpl::mappers;
	session->changes().peerUpdates(
		Data::PeerUpdate::Flag::FullInfo
	) | rpl::filter([](const Data::PeerUpdate &update) {
		return update.peer->isChat() || update.peer->isMegagroup();
	}) | rpl::on_next([=](const Data::PeerUpdate &update) {
		const auto peer = update.peer;
		if (const auto list = _pendingSpeakingCallParticipants.take(peer)) {
			if (const auto call = peer->groupCall()) {
				for (const auto &[participantPeerId, when] : *list) {
					call->applyActiveUpdate(
						participantPeerId,
						Data::LastSpokeTimes{
							.anything = when,
							.voice = when
						},
						peer->owner().peerLoaded(participantPeerId));
				}
			}
		}
	}, _lifetime);
}

Main::Session &Updates::session() const {
	return *_session;
}

ApiWrap &Updates::api() const {
	return _session->api();
}

void Updates::checkLastUpdate(bool afterSleep) {
	const auto now = crl::now();
	const auto skip = afterSleep
		? kNoUpdatesAfterSleepTimeout
		: kNoUpdatesTimeout;
	if (_lastUpdateTime && now > _lastUpdateTime + skip) {
		_lastUpdateTime = now;
		sendPing();
	}
}

void Updates::feedUpdateVector(
		const MTPVector<MTPUpdate> &updates,
		SkipUpdatePolicy policy) {
	auto list = updates.v;
	const auto hasGroupCallParticipantUpdates = ranges::contains(
		list,
		true,
		[](const MTPUpdate &update) {
			return update.type() == mtpc_updateGroupCallParticipants
				|| update.type() == mtpc_updateGroupCallChainBlocks;
		});
	if (hasGroupCallParticipantUpdates) {
		ranges::stable_sort(list, std::less<>(), [](const MTPUpdate &entry) {
			if (entry.type() == mtpc_updateGroupCallChainBlocks) {
				return 0;
			} else if (entry.type() == mtpc_updateGroupCallParticipants) {
				return 1;
			} else {
				return 2;
			}
		});
	} else if (policy == SkipUpdatePolicy::SkipExceptGroupCallParticipants) {
		return;
	}
	if (policy == SkipUpdatePolicy::SkipNone) {
		applyConvertToScheduledOnSend(updates);
	}
	for (const auto &entry : std::as_const(list)) {
		const auto type = entry.type();
		if ((policy == SkipUpdatePolicy::SkipMessageIds
			&& type == mtpc_updateMessageID)
			|| (policy == SkipUpdatePolicy::SkipExceptGroupCallParticipants
				&& type != mtpc_updateGroupCallParticipants
				&& type != mtpc_updateGroupCallChainBlocks)) {
			continue;
		}
		feedUpdate(entry);
	}
	session().data().sendHistoryChangeNotifications();
}

void Updates::checkForSentToScheduled(const MTPUpdates &updates) {
	updates.match([&](const MTPDupdates &data) {
		applyConvertToScheduledOnSend(data.vupdates(), true);
	}, [&](const MTPDupdatesCombined &data) {
		applyConvertToScheduledOnSend(data.vupdates(), true);
	}, [](const auto &) {
	});
}

void Updates::feedMessageIds(const MTPVector<MTPUpdate> &updates) {
	for (const auto &update : updates.v) {
		if (update.type() == mtpc_updateMessageID) {
			feedUpdate(update);
		}
	}
}

void Updates::setState(int32 pts, int32 date, int32 qts, int32 seq) {
	if (pts) {
		_ptsWaiter.init(pts);
	}
	if (_updatesDate < date && !_byMinChannelTimer.isActive()) {
		_updatesDate = date;
	}
	if (qts && _updatesQts < qts) {
		_updatesQts = qts;
	}
	if (seq && seq != _updatesSeq) {
		_updatesSeq = seq;
		if (_bySeqTimer.isActive()) {
			_bySeqTimer.cancel();
		}
		while (!_bySeqUpdates.empty()) {
			const auto s = _bySeqUpdates.front().first;
			if (s <= seq + 1) {
				const auto v = _bySeqUpdates.front().second;
				_bySeqUpdates.erase(_bySeqUpdates.begin());
				if (s == seq + 1) {
					return applyUpdates(v);
				}
			} else {
				if (!_bySeqTimer.isActive()) {
					_bySeqTimer.callOnce(PtsWaiter::kWaitForSkippedTimeout);
				}
				break;
			}
		}
	}
}

void Updates::channelDifferenceDone(
		not_null<ChannelData*> channel,
		const MTPupdates_ChannelDifference &difference) {
	_channelFailDifferenceTimeout.remove(channel);

	const auto timeout = difference.match([&](const auto &data) {
		return data.vtimeout().value_or_empty();
	});
	const auto isFinal = difference.match([&](const auto &data) {
		return data.is_final();
	});
	difference.match([&](const MTPDupdates_channelDifferenceEmpty &data) {
		channel->ptsInit(data.vpts().v);
	}, [&](const MTPDupdates_channelDifferenceTooLong &data) {
		session().data().processUsers(data.vusers());
		session().data().processChats(data.vchats());
		const auto history = session().data().historyLoaded(channel->id);
		if (history) {
			history->setNotLoadedAtBottom();
			requestChannelRangeDifference(history);
		}
		data.vdialog().match([&](const MTPDdialog &data) {
			if (const auto pts = data.vpts()) {
				channel->ptsInit(pts->v);
			}
		}, [&](const MTPDdialogFolder &) {
		});
		session().data().applyDialogs(
			nullptr,
			data.vmessages().v,
			QVector<MTPDialog>(1, data.vdialog()));
		session().data().channelDifferenceTooLong(channel);
		if (const auto forum = channel->forum()) {
			forum->reloadTopics();
		}
	}, [&](const MTPDupdates_channelDifference &data) {
		feedChannelDifference(data);
		channel->ptsInit(data.vpts().v);
	});

	channel->ptsSetRequesting(false);

	if (!isFinal) {
		MTP_LOG(0, ("getChannelDifference "
			"{ good - after not final channelDifference was received }%1"
			).arg(_session->mtp().isTestMode() ? " TESTMODE" : ""));
		getChannelDifference(channel);
	} else if (inActiveChats(channel)) {
		channel->ptsSetWaitingForShortPoll(timeout
			? (timeout * crl::time(1000))
			: kWaitForChannelGetDifference);
	} else {
		channel->ptsSetWaitingForShortPoll(-1);
	}
}

void Updates::feedChannelDifference(
		const MTPDupdates_channelDifference &data) {
	session().data().processUsers(data.vusers());
	session().data().processChats(data.vchats());

	_handlingChannelDifference = true;
	applyConvertToScheduledOnSend(data.vother_updates());
	feedMessageIds(data.vother_updates());
	session().data().processMessages(
		data.vnew_messages(),
		NewMessageType::Unread);
	feedUpdateVector(
		data.vother_updates(),
		SkipUpdatePolicy::SkipMessageIds);
	_handlingChannelDifference = false;
}

void Updates::channelDifferenceFail(
		not_null<ChannelData*> channel,
		const MTP::Error &error) {
	LOG(("RPC Error in getChannelDifference: %1 %2: %3").arg(
		QString::number(error.code()),
		error.type(),
		error.description()));
	failDifferenceStartTimerFor(channel);
}

void Updates::stateDone(const MTPupdates_State &state) {
	const auto &d = state.c_updates_state();
	setState(d.vpts().v, d.vdate().v, d.vqts().v, d.vseq().v);

	_lastUpdateTime = crl::now();
	_noUpdatesTimer.callOnce(kNoUpdatesTimeout);
	_ptsWaiter.setRequesting(false);

	session().api().requestDialogs();
	updateOnline();
}

void Updates::differenceDone(const MTPupdates_Difference &result) {
	_failDifferenceTimeout = 1;

	switch (result.type()) {
	case mtpc_updates_differenceEmpty: {
		auto &d = result.c_updates_differenceEmpty();
		setState(_ptsWaiter.current(), d.vdate().v, _updatesQts, d.vseq().v);

		_lastUpdateTime = crl::now();
		_noUpdatesTimer.callOnce(kNoUpdatesTimeout);

		_ptsWaiter.setRequesting(false);
	} break;
	case mtpc_updates_differenceSlice: {
		auto &d = result.c_updates_differenceSlice();
		feedDifference(d.vusers(), d.vchats(), d.vnew_messages(), d.vother_updates());

		auto &s = d.vintermediate_state().c_updates_state();
		setState(s.vpts().v, s.vdate().v, s.vqts().v, s.vseq().v);

		_ptsWaiter.setRequesting(false);

		MTP_LOG(0, ("getDifference "
			"{ good - after a slice of difference was received }%1"
			).arg(_session->mtp().isTestMode() ? " TESTMODE" : ""));
		getDifference();
	} break;
	case mtpc_updates_difference: {
		auto &d = result.c_updates_difference();
		feedDifference(d.vusers(), d.vchats(), d.vnew_messages(), d.vother_updates());

		stateDone(d.vstate());
	} break;
	case mtpc_updates_differenceTooLong: {
		LOG(("API Error: updates.differenceTooLong is not supported by Telegram Desktop!"));
	} break;
	};
}

bool Updates::whenGetDiffChanged(
		ChannelData *channel,
		int32 ms,
		base::flat_map<not_null<ChannelData*>, crl::time> &whenMap,
		crl::time &curTime) {
	if (channel) {
		if (ms <= 0) {
			const auto i = whenMap.find(channel);
			if (i != whenMap.cend()) {
				whenMap.erase(i);
			} else {
				return false;
			}
		} else {
			auto when = crl::now() + ms;
			const auto i = whenMap.find(channel);
			if (i != whenMap.cend()) {
				if (i->second > when) {
					i->second = when;
				} else {
					return false;
				}
			} else {
				whenMap.emplace(channel, when);
			}
		}
	} else {
		if (ms <= 0) {
			if (curTime) {
				curTime = 0;
			} else {
				return false;
			}
		} else {
			auto when = crl::now() + ms;
			if (!curTime || curTime > when) {
				curTime = when;
			} else {
				return false;
			}
		}
	}
	return true;
}

void Updates::ptsWaiterStartTimerFor(ChannelData *channel, crl::time ms) {
	if (whenGetDiffChanged(channel, ms, _whenGetDiffByPts, _getDifferenceTimeByPts)) {
		getDifferenceByPts();
	}
}

void Updates::failDifferenceStartTimerFor(ChannelData *channel) {
	auto &timeout = [&]() -> crl::time & {
		if (!channel) {
			return _failDifferenceTimeout;
		}
		const auto i = _channelFailDifferenceTimeout.find(channel);
		return (i == _channelFailDifferenceTimeout.end())
			? _channelFailDifferenceTimeout.emplace(channel, 1).first->second
			: i->second;
	}();
	if (whenGetDiffChanged(channel, timeout * 1000, _whenGetDiffAfterFail, _getDifferenceTimeAfterFail)) {
		getDifferenceAfterFail();
	}
	if (timeout < 64) timeout *= 2;
}

bool Updates::updateAndApply(
		int32 pts,
		int32 ptsCount,
		const MTPUpdates &updates) {
	return _ptsWaiter.updateAndApply(nullptr, pts, ptsCount, updates);
}

bool Updates::updateAndApply(
		int32 pts,
		int32 ptsCount,
		const MTPUpdate &update) {
	return _ptsWaiter.updateAndApply(nullptr, pts, ptsCount, update);
}

bool Updates::updateAndApply(int32 pts, int32 ptsCount) {
	return _ptsWaiter.updateAndApply(nullptr, pts, ptsCount);
}

void Updates::feedDifference(
		const MTPVector<MTPUser> &users,
		const MTPVector<MTPChat> &chats,
		const MTPVector<MTPMessage> &msgs,
		const MTPVector<MTPUpdate> &other) {
	Core::App().checkAutoLock();
	session().data().processUsers(users);
	session().data().processChats(chats);
	applyConvertToScheduledOnSend(other);
	feedMessageIds(other);
	session().data().processMessages(msgs, NewMessageType::Unread);
	feedUpdateVector(other, SkipUpdatePolicy::SkipMessageIds);
}

void Updates::differenceFail(const MTP::Error &error) {
	LOG(("RPC Error in getDifference: %1 %2: %3").arg(
		QString::number(error.code()),
		error.type(),
		error.description()));
	failDifferenceStartTimerFor(nullptr);
}

void Updates::getDifferenceByPts() {
	auto now = crl::now(), wait = crl::time(0);
	if (_getDifferenceTimeByPts) {
		if (_getDifferenceTimeByPts > now) {
			wait = _getDifferenceTimeByPts - now;
		} else {
			getDifference();
		}
	}
	for (auto i = _whenGetDiffByPts.begin(); i != _whenGetDiffByPts.cend();) {
		if (i->second > now) {
			wait = wait ? std::min(wait, i->second - now) : (i->second - now);
			++i;
		} else {
			getChannelDifference(
				i->first,
				ChannelDifferenceRequest::PtsGapOrShortPoll);
			i = _whenGetDiffByPts.erase(i);
		}
	}
	if (wait) {
		_byPtsTimer.callOnce(wait);
	} else {
		_byPtsTimer.cancel();
	}
}

void Updates::getDifferenceAfterFail() {
	auto now = crl::now(), wait = crl::time(0);
	if (_getDifferenceTimeAfterFail) {
		if (_getDifferenceTimeAfterFail > now) {
			wait = _getDifferenceTimeAfterFail - now;
		} else {
			_ptsWaiter.setRequesting(false);
			MTP_LOG(0, ("getDifference "
				"{ force - after get difference failed }%1"
				).arg(_session->mtp().isTestMode() ? " TESTMODE" : ""));
			getDifference();
		}
	}
	for (auto i = _whenGetDiffAfterFail.begin(); i != _whenGetDiffAfterFail.cend();) {
		if (i->second > now) {
			wait = wait ? std::min(wait, i->second - now) : (i->second - now);
			++i;
		} else {
			i->first->ptsSetRequesting(false);
			getChannelDifference(i->first, ChannelDifferenceRequest::AfterFail);
			i = _whenGetDiffAfterFail.erase(i);
		}
	}
	if (wait) {
		_failDifferenceTimer.callOnce(wait);
	} else {
		_failDifferenceTimer.cancel();
	}
}

void Updates::getDifference() {
	_getDifferenceTimeByPts = 0;

	if (requestingDifference()) {
		return;
	}

	_bySeqUpdates.clear();
	_bySeqTimer.cancel();

	_noUpdatesTimer.cancel();
	_getDifferenceTimeAfterFail = 0;

	_ptsWaiter.setRequesting(true);

	api().request(MTPupdates_GetDifference(
		MTP_flags(0),
		MTP_int(_ptsWaiter.current()),
		MTPint(), // pts_limit
		MTPint(), // pts_total_limit
		MTP_int(_updatesDate),
		MTP_int(_updatesQts),
		MTPint() // qts_limit
	)).done([=](const MTPupdates_Difference &result) {
		differenceDone(result);
	}).fail([=](const MTP::Error &error) {
		differenceFail(error);
	}).send();
}

void Updates::getChannelDifference(
		not_null<ChannelData*> channel,
		ChannelDifferenceRequest from) {
	if (from != ChannelDifferenceRequest::PtsGapOrShortPoll) {
		_whenGetDiffByPts.remove(channel);
	}

	if (!channel->ptsInited() || channel->ptsRequesting()) {
		return;
	}

	if (from != ChannelDifferenceRequest::AfterFail) {
		_whenGetDiffAfterFail.remove(channel);
	}

	channel->ptsSetRequesting(true);

	auto filter = MTP_channelMessagesFilterEmpty();
	auto flags = MTPupdates_GetChannelDifference::Flag::f_force | 0;
	if (from != ChannelDifferenceRequest::PtsGapOrShortPoll) {
		if (!channel->ptsWaitingForSkipped()) {
			flags = 0; // No force flag when requesting for short poll.
		}
	}
	api().request(MTPupdates_GetChannelDifference(
		MTP_flags(flags),
		channel->inputChannel(),
		filter,
		MTP_int(channel->pts()),
		MTP_int(kChannelGetDifferenceLimit)
	)).done([=](const MTPupdates_ChannelDifference &result) {
		channelDifferenceDone(channel, result);
	}).fail([=](const MTP::Error &error) {
		channelDifferenceFail(channel, error);
	}).send();
}

void Updates::sendPing() {
	_session->mtp().ping();
}

void Updates::addActiveChat(rpl::producer<PeerData*> chat) {
	const auto key = _activeChats.empty() ? 0 : _activeChats.back().first + 1;
	std::move(
		chat
	) | rpl::on_next_done([=](PeerData *peer) {
		auto &active = _activeChats[key];
		const auto was = active.peer;
		if (was != peer) {
			active.peer = peer;
			if (const auto channel = was ? was->asChannel() : nullptr) {
				if (!inActiveChats(channel)) {
					channel->ptsSetWaitingForShortPoll(-1);
				}
			}
			if (const auto channel = peer ? peer->asChannel() : nullptr) {
				channel->ptsSetWaitingForShortPoll(
					kWaitForChannelGetDifference);
			}
		}
	}, [=] {
		_activeChats.erase(key);
	}, _activeChats[key].lifetime);
}

bool Updates::inActiveChats(not_null<PeerData*> peer) const {
	return ranges::contains(
		_activeChats,
		peer.get(),
		[](const auto &pair) { return pair.second.peer; });
}

void Updates::requestChannelRangeDifference(not_null<History*> history) {
	Expects(history->peer->isChannel());

	const auto channel = history->peer->asChannel();
	if (const auto requestId = _rangeDifferenceRequests.take(channel)) {
		api().request(*requestId).cancel();
	}
	const auto range = history->rangeForDifferenceRequest();
	if (!(range.from < range.till) || !channel->pts()) {
		return;
	}

	MTP_LOG(0, ("getChannelDifference "
		"{ good - after channelDifferenceTooLong was received, "
		"validating history part }%1"
		).arg(_session->mtp().isTestMode() ? " TESTMODE" : ""));
	channelRangeDifferenceSend(channel, range, channel->pts());
}

void Updates::channelRangeDifferenceSend(
		not_null<ChannelData*> channel,
		MsgRange range,
		int32 pts) {
	Expects(range.from < range.till);

	const auto limit = range.till - range.from;
	const auto filter = MTP_channelMessagesFilter(
		MTP_flags(0),
		MTP_vector<MTPMessageRange>(1, MTP_messageRange(
			MTP_int(range.from),
			MTP_int(range.till - 1))));
	const auto requestId = api().request(MTPupdates_GetChannelDifference(
		MTP_flags(MTPupdates_GetChannelDifference::Flag::f_force),
		channel->inputChannel(),
		filter,
		MTP_int(pts),
		MTP_int(limit)
	)).done([=](const MTPupdates_ChannelDifference &result) {
		_rangeDifferenceRequests.remove(channel);
		channelRangeDifferenceDone(channel, range, result);
	}).fail([=] {
		_rangeDifferenceRequests.remove(channel);
	}).send();
	_rangeDifferenceRequests.emplace(channel, requestId);
}

void Updates::channelRangeDifferenceDone(
		not_null<ChannelData*> channel,
		MsgRange range,
		const MTPupdates_ChannelDifference &result) {
	auto nextRequestPts = int32(0);
	auto isFinal = true;

	switch (result.type()) {
	case mtpc_updates_channelDifferenceEmpty: {
		const auto &d = result.c_updates_channelDifferenceEmpty();
		nextRequestPts = d.vpts().v;
		isFinal = d.is_final();
	} break;

	case mtpc_updates_channelDifferenceTooLong: {
		const auto &d = result.c_updates_channelDifferenceTooLong();

		_session->data().processUsers(d.vusers());
		_session->data().processChats(d.vchats());

		nextRequestPts = d.vdialog().match([&](const MTPDdialog &data) {
			return data.vpts().value_or_empty();
		}, [&](const MTPDdialogFolder &data) {
			return 0;
		});
		isFinal = d.is_final();
	} break;

	case mtpc_updates_channelDifference: {
		const auto &d = result.c_updates_channelDifference();

		feedChannelDifference(d);

		nextRequestPts = d.vpts().v;
		isFinal = d.is_final();
	} break;
	}

	if (!isFinal && nextRequestPts) {
		MTP_LOG(0, ("getChannelDifference "
			"{ good - after not final channelDifference was received, "
			"validating history part }%1"
			).arg(_session->mtp().isTestMode() ? " TESTMODE" : ""));
		channelRangeDifferenceSend(channel, range, nextRequestPts);
	}
}

void Updates::mtpNewSessionCreated() {
	Core::App().checkAutoLock();
	_updatesSeq = 0;
	MTP_LOG(0, ("getDifference { after new_session_created }%1"
		).arg(_session->mtp().isTestMode() ? " TESTMODE" : ""));
	getDifference();
}

void Updates::mtpUpdateReceived(const MTPUpdates &updates) {
	Core::App().checkAutoLock();
	_lastUpdateTime = crl::now();
	_noUpdatesTimer.callOnce(kNoUpdatesTimeout);
	if (!requestingDifference()
		|| HasForceLogoutNotification(updates)) {
		applyUpdates(updates);
	} else {
		applyGroupCallParticipantUpdates(updates);
	}
}

void Updates::applyConvertToScheduledOnSend(
		const MTPVector<MTPUpdate> &other,
		bool skipScheduledCheck) {
	for (const auto &update : other.v) {
		update.match([&](const MTPDupdateNewScheduledMessage &data) {
			const auto &message = data.vmessage();
			const auto id = IdFromMessage(message);
			const auto scheduledMessages = &_session->scheduledMessages();
			const auto scheduledId = scheduledMessages->localMessageId(id);
			for (const auto &updateId : other.v) {
				updateId.match([&](const MTPDupdateMessageID &dataId) {
					if (dataId.vid().v == id) {
						auto &owner = session().data();
						if (skipScheduledCheck) {
							const auto peerId = PeerFromMessage(message);
							const auto history = owner.historyLoaded(peerId);
							if (history) {
								_session->data().sentToScheduled({
									.history = history,
									.scheduledId = scheduledId,
								});
							}
							return;
						}
						const auto rand = dataId.vrandom_id().v;
						const auto localId = owner.messageIdByRandomId(rand);
						if (const auto local = owner.message(localId)) {
							if (!local->isScheduled()) {
								_session->data().sentToScheduled({
									.history = local->history(),
									.scheduledId = scheduledId,
								});

								// We've sent a non-scheduled message,
								// but it was converted to a scheduled.
								local->destroy();
							}
						}
					}
				}, [](const auto &) {});
			}
		}, [](const auto &) {});
	}
}

void Updates::applyGroupCallParticipantUpdates(const MTPUpdates &updates) {
	updates.match([&](const MTPDupdates &data) {
		session().data().processUsers(data.vusers());
		session().data().processChats(data.vchats());
		feedUpdateVector(
			data.vupdates(),
			SkipUpdatePolicy::SkipExceptGroupCallParticipants);
	}, [&](const MTPDupdatesCombined &data) {
		session().data().processUsers(data.vusers());
		session().data().processChats(data.vchats());
		feedUpdateVector(
			data.vupdates(),
			SkipUpdatePolicy::SkipExceptGroupCallParticipants);
	}, [&](const MTPDupdateShort &data) {
		if (data.vupdate().type() == mtpc_updateGroupCallParticipants
			|| data.vupdate().type() == mtpc_updateGroupCallChainBlocks) {
			feedUpdate(data.vupdate());
		}
	}, [](const auto &) {
	});
}

int32 Updates::pts() const {
	return _ptsWaiter.current();
}

void Updates::updateOnline(crl::time lastNonIdleTime) {
	updateOnline(lastNonIdleTime, false);
}

bool Updates::isIdle() const {
	return _isIdle.current();
}

rpl::producer<bool> Updates::isIdleValue() const {
	return _isIdle.value();
}

void Updates::updateOnline(crl::time lastNonIdleTime, bool gotOtherOffline) {
	if (!lastNonIdleTime) {
		lastNonIdleTime = Core::App().lastNonIdleTime();
	}
	crl::on_main(&session(), [=] {
		Core::App().checkAutoLock(lastNonIdleTime);
	});

	const auto &config = _session->serverConfig();
	bool isOnline = Core::App().hasActiveWindow(&session());
	int updateIn = config.onlineUpdatePeriod;
	Assert(updateIn >= 0);
	if (isOnline) {
		const auto idle = crl::now() - lastNonIdleTime;
		if (idle >= config.offlineIdleTimeout) {
			isOnline = false;
			if (!isIdle()) {
				_isIdle = true;
				_idleFinishTimer.callOnce(900);
			}
		} else {
			updateIn = qMin(updateIn, int(config.offlineIdleTimeout - idle));
			Assert(updateIn >= 0);
		}
	}
	auto ms = crl::now();
	if (isOnline != _lastWasOnline
		|| (isOnline && _lastSetOnline + config.onlineUpdatePeriod <= ms)
		|| (isOnline && gotOtherOffline)) {
		api().request(base::take(_onlineRequest)).cancel();

		_lastWasOnline = isOnline;
		_lastSetOnline = ms;
		if (!Core::Quitting()) {
			_onlineRequest = api().request(MTPaccount_UpdateStatus(
				MTP_bool(!isOnline)
			)).send();
		} else {
			_onlineRequest = api().request(MTPaccount_UpdateStatus(
				MTP_bool(!isOnline)
			)).done([=] {
				Core::App().quitPreventFinished();
			}).fail([=] {
				Core::App().quitPreventFinished();
			}).send();
		}

		const auto self = session().user();
		const auto onlineFor = (config.onlineUpdatePeriod / 1000);
		self->updateLastseen(Data::LastseenStatus::OnlineTill(
			base::unixtime::now() + (isOnline ? onlineFor : -1)));
		session().changes().peerUpdated(
			self,
			Data::PeerUpdate::Flag::OnlineStatus);
		if (!isOnline) { // Went offline, so we need to save message draft to the cloud.
			api().saveCurrentDraftToCloud();
			session().data().maybeStopWatchForOffline(self);
		}

		_lastSetOnline = ms;
	} else if (isOnline) {
		updateIn = qMin(updateIn, int(_lastSetOnline + config.onlineUpdatePeriod - ms));
		Assert(updateIn >= 0);
	}
	_onlineTimer.callOnce(updateIn);
}

void Updates::checkIdleFinish(crl::time lastNonIdleTime) {
	if (!lastNonIdleTime) {
		lastNonIdleTime = Core::App().lastNonIdleTime();
	}
	if (crl::now() - lastNonIdleTime
		< _session->serverConfig().offlineIdleTimeout) {
		updateOnline(lastNonIdleTime);
		_idleFinishTimer.cancel();
		_isIdle = false;
	} else {
		_idleFinishTimer.callOnce(900);
	}
}

bool Updates::lastWasOnline() const {
	return _lastWasOnline;
}

crl::time Updates::lastSetOnline() const {
	return _lastSetOnline;
}

bool Updates::isQuitPrevent() {
	if (!_lastWasOnline) {
		return false;
	}
	LOG(("Api::Updates prevents quit, sending offline status..."));
	updateOnline(crl::now());
	return true;
}

void Updates::handleSendActionUpdate(
		PeerId peerId,
		MsgId rootId,
		PeerId fromId,
		const MTPSendMessageAction &action) {
	const auto history = session().data().historyLoaded(peerId);
	if (!history) {
		return;
	}
	const auto peer = history->peer;
	const auto from = (fromId == session().userPeerId())
		? session().user().get()
		: session().data().peerLoaded(fromId);
	const auto when = requestingDifference()
		? 0
		: base::unixtime::now();
	if (action.type() == mtpc_speakingInGroupCallAction) {
		handleSpeakingInCall(peer, fromId, from);
	}
	if (!from || !from->isUser() || from->isSelf()) {
		return;
	} else if (action.type() == mtpc_sendMessageEmojiInteraction) {
		handleEmojiInteraction(peer, action.c_sendMessageEmojiInteraction());
		return;
	} else if (action.type() == mtpc_sendMessageEmojiInteractionSeen) {
		const auto &data = action.c_sendMessageEmojiInteractionSeen();
		handleEmojiInteraction(peer, qs(data.vemoticon()));
		return;
	} else if (action.type() == mtpc_sendMessageTextDraftAction) {
		const auto &data = action.c_sendMessageTextDraftAction();
		history->streamedDrafts().apply(rootId, fromId, when, data);
		return;
	}
	session().data().sendActionManager().registerFor(
		history,
		rootId,
		from->asUser(),
		action,
		when);
}

void Updates::handleEmojiInteraction(
		not_null<PeerData*> peer,
		const MTPDsendMessageEmojiInteraction &data) {
	const auto json = data.vinteraction().match([&](
			const MTPDdataJSON &data) {
		return data.vdata().v;
	});
	handleEmojiInteraction(
		peer,
		data.vmsg_id().v,
		qs(data.vemoticon()),
		ChatHelpers::EmojiInteractions::Parse(json));
}

void Updates::handleSpeakingInCall(
		not_null<PeerData*> peer,
		PeerId participantPeerId,
		PeerData *participantPeerLoaded) {
	if (!peer->isChat() && !peer->isChannel()) {
		return;
	}
	const auto call = peer->groupCall();
	const auto now = crl::now();
	if (call) {
		call->applyActiveUpdate(
			participantPeerId,
			Data::LastSpokeTimes{ .anything = now, .voice = now },
			participantPeerLoaded);
	} else {
		const auto chat = peer->asChat();
		const auto channel = peer->asChannel();
		const auto active = chat
			? (chat->flags() & ChatDataFlag::CallActive)
			: (channel->flags() & ChannelDataFlag::CallActive);
		if (active) {
			_pendingSpeakingCallParticipants.emplace(
				peer).first->second[participantPeerId] = now;
			if (peerIsUser(participantPeerId)) {
				session().api().requestFullPeer(peer);
			}
		}
	}
}

void Updates::handleEmojiInteraction(
		not_null<PeerData*> peer,
		MsgId messageId,
		const QString &emoticon,
		ChatHelpers::EmojiInteractionsBunch bunch) {
	if (session().windows().empty()) {
		return;
	}
	const auto window = session().windows().front();
	window->emojiInteractions().startIncoming(
		peer,
		messageId,
		emoticon,
		std::move(bunch));
}

void Updates::handleEmojiInteraction(
		not_null<PeerData*> peer,
		const QString &emoticon) {
	if (session().windows().empty()) {
		return;
	}
	const auto window = session().windows().front();
	window->emojiInteractions().seenOutgoing(peer, emoticon);
}

void Updates::applyUpdatesNoPtsCheck(const MTPUpdates &updates) {
	switch (updates.type()) {
	case mtpc_updateShortMessage: {
		const auto &d = updates.c_updateShortMessage();
		const auto flags = mtpCastFlags(d.vflags().v)
			| MTPDmessage::Flag::f_from_id;
		_session->data().addNewMessage(
			MTP_message(
				MTP_flags(flags),
				d.vid(),
				(d.is_out()
					? peerToMTP(_session->userPeerId())
					: MTP_peerUser(d.vuser_id())),
				MTPint(), // from_boosts_applied
				MTP_peerUser(d.vuser_id()),
				MTPPeer(), // saved_peer_id
				d.vfwd_from() ? *d.vfwd_from() : MTPMessageFwdHeader(),
				MTP_long(d.vvia_bot_id().value_or_empty()),
				MTPlong(), // via_business_bot_id
				d.vreply_to() ? *d.vreply_to() : MTPMessageReplyHeader(),
				d.vdate(),
				d.vmessage(),
				MTP_messageMediaEmpty(),
				MTPReplyMarkup(),
				MTP_vector<MTPMessageEntity>(d.ventities().value_or_empty()),
				MTPint(), // views
				MTPint(), // forwards
				MTPMessageReplies(),
				MTPint(), // edit_date
				MTPstring(),
				MTPlong(),
				MTPMessageReactions(),
				MTPVector<MTPRestrictionReason>(),
				MTP_int(d.vttl_period().value_or_empty()),
				MTPint(), // quick_reply_shortcut_id
				MTPlong(), // effect
				MTPFactCheck(),
				MTPint(), // report_delivery_until_date
				MTPlong(), // paid_message_stars
				MTPSuggestedPost(),
				MTPint(), // schedule_repeat_period
				MTPstring()), // summary_from_language
			MessageFlags(),
			NewMessageType::Unread);
	} break;

	case mtpc_updateShortChatMessage: {
		const auto &d = updates.c_updateShortChatMessage();
		const auto flags = mtpCastFlags(d.vflags().v)
			| MTPDmessage::Flag::f_from_id;
		_session->data().addNewMessage(
			MTP_message(
				MTP_flags(flags),
				d.vid(),
				MTP_peerUser(d.vfrom_id()),
				MTPint(), // from_boosts_applied
				MTP_peerChat(d.vchat_id()),
				MTPPeer(), // saved_peer_id
				d.vfwd_from() ? *d.vfwd_from() : MTPMessageFwdHeader(),
				MTP_long(d.vvia_bot_id().value_or_empty()),
				MTPlong(), // via_business_bot_id
				d.vreply_to() ? *d.vreply_to() : MTPMessageReplyHeader(),
				d.vdate(),
				d.vmessage(),
				MTP_messageMediaEmpty(),
				MTPReplyMarkup(),
				MTP_vector<MTPMessageEntity>(d.ventities().value_or_empty()),
				MTPint(), // views
				MTPint(), // forwards
				MTPMessageReplies(),
				MTPint(), // edit_date
				MTPstring(),
				MTPlong(),
				MTPMessageReactions(),
				MTPVector<MTPRestrictionReason>(),
				MTP_int(d.vttl_period().value_or_empty()),
				MTPint(), // quick_reply_shortcut_id
				MTPlong(), // effect
				MTPFactCheck(),
				MTPint(), // report_delivery_until_date
				MTPlong(), // paid_message_stars
				MTPSuggestedPost(),
				MTPint(), // schedule_repeat_period
				MTPstring()), // summary_from_language
			MessageFlags(),
			NewMessageType::Unread);
	} break;

	case mtpc_updateShortSentMessage: {
		auto &d = updates.c_updateShortSentMessage();
		Q_UNUSED(d); // Sent message data was applied anyway.
	} break;

	default: Unexpected("Type in applyUpdatesNoPtsCheck()");
	}
}

void Updates::applyUpdateNoPtsCheck(const MTPUpdate &update) {
	switch (update.type()) {
	case mtpc_updateNewMessage: {
		auto &d = update.c_updateNewMessage();
		auto needToAdd = true;
		if (d.vmessage().type() == mtpc_message) { // index forwarded messages to links _overview
			const auto &data = d.vmessage().c_message();
			if (_session->data().updateExistingMessage(data)) { // already in blocks
				LOG(("Skipping message, because it is already in blocks!"));
				needToAdd = false;
			}
			ProcessScheduledMessageWithElapsedTime(_session, needToAdd, data);
		}
		if (needToAdd) {
			_session->data().addNewMessage(
				d.vmessage(),
				MessageFlags(),
				NewMessageType::Unread);
		}
	} break;

	case mtpc_updateReadMessagesContents: {
		const auto &d = update.c_updateReadMessagesContents();
		auto unknownReadIds = base::flat_set<MsgId>();
		for (const auto &msgId : d.vmessages().v) {
			if (const auto item = _session->data().nonChannelMessage(msgId.v)) {
				if (item->isUnreadMedia() || item->isUnreadMention()) {
					item->markMediaAndMentionRead();
					_session->data().requestItemRepaint(item);

					if (item->out()) {
						const auto user = item->history()->peer->asUser();
						if (user && !requestingDifference()) {
							user->madeAction(base::unixtime::now());
						}
					}
					item->clearMediaAsExpired();
				}
			} else {
				// Perhaps it was an unread mention!
				unknownReadIds.insert(msgId.v);
			}
		}
		session().api().unreadThings().mediaAndMentionsRead(unknownReadIds);
	} break;

	case mtpc_updateReadHistoryInbox: {
		const auto &d = update.c_updateReadHistoryInbox();
		const auto peer = peerFromMTP(d.vpeer());
		if (const auto history = _session->data().historyLoaded(peer)) {
			const auto folderId = d.vfolder_id().value_or_empty();
			history->applyInboxReadUpdate(
				folderId,
				d.vmax_id().v,
				d.vstill_unread_count().v);
		}
	} break;

	case mtpc_updateReadHistoryOutbox: {
		const auto &d = update.c_updateReadHistoryOutbox();
		const auto peer = peerFromMTP(d.vpeer());
		if (const auto history = _session->data().historyLoaded(peer)) {
			history->outboxRead(d.vmax_id().v);
			if (!requestingDifference()) {
				if (const auto user = history->peer->asUser()) {
					user->madeAction(base::unixtime::now());
				}
			}
		}
	} break;

	case mtpc_updateWebPage: {
		auto &d = update.c_updateWebPage();
		Q_UNUSED(d); // Web page was updated anyway.
	} break;

	case mtpc_updateFolderPeers: {
		const auto &data = update.c_updateFolderPeers();
		auto &owner = _session->data();
		for (const auto &peer : data.vfolder_peers().v) {
			peer.match([&](const MTPDfolderPeer &data) {
				const auto peerId = peerFromMTP(data.vpeer());
				if (const auto history = owner.historyLoaded(peerId)) {
					if (const auto folderId = data.vfolder_id().v) {
						history->setFolder(owner.folder(folderId));
					} else {
						history->clearFolder();
					}
				}
			});
		}
	} break;

	case mtpc_updateDeleteMessages: {
		auto &d = update.c_updateDeleteMessages();
		_session->data().processNonChannelMessagesDeleted(d.vmessages().v);
	} break;

	case mtpc_updateNewChannelMessage: {
		auto &d = update.c_updateNewChannelMessage();
		auto needToAdd = true;
		if (d.vmessage().type() == mtpc_message) { // index forwarded messages to links _overview
			const auto &data = d.vmessage().c_message();
			if (_session->data().updateExistingMessage(data)) { // already in blocks
				LOG(("Skipping message, because it is already in blocks!"));
				needToAdd = false;
			}
			ProcessScheduledMessageWithElapsedTime(_session, needToAdd, data);
		}
		if (needToAdd) {
			_session->data().addNewMessage(
				d.vmessage(),
				MessageFlags(),
				NewMessageType::Unread);
		}
	} break;

	case mtpc_updateEditChannelMessage: {
		auto &d = update.c_updateEditChannelMessage();
		_session->data().updateEditedMessage(d.vmessage());
	} break;

	case mtpc_updatePinnedChannelMessages: {
		const auto &d = update.c_updatePinnedChannelMessages();
		const auto peerId = peerFromChannel(d.vchannel_id());
		for (const auto &msgId : d.vmessages().v) {
			const auto item = session().data().message(peerId, msgId.v);
			if (item) {
				item->setIsPinned(d.is_pinned());
			}
		}
	} break;

	case mtpc_updateEditMessage: {
		auto &d = update.c_updateEditMessage();
		_session->data().updateEditedMessage(d.vmessage());
	} break;

	case mtpc_updateChannelWebPage: {
		auto &d = update.c_updateChannelWebPage();
		Q_UNUSED(d); // Web page was updated anyway.
	} break;

	case mtpc_updateDeleteChannelMessages: {
		auto &d = update.c_updateDeleteChannelMessages();
		_session->data().processMessagesDeleted(
			peerFromChannel(d.vchannel_id().v),
			d.vmessages().v);
	} break;

	case mtpc_updatePinnedMessages: {
		const auto &d = update.c_updatePinnedMessages();
		const auto peerId = peerFromMTP(d.vpeer());
		for (const auto &msgId : d.vmessages().v) {
			const auto item = session().data().message(peerId, msgId.v);
			if (item) {
				item->setIsPinned(d.is_pinned());
			}
		}
	} break;

	default: Unexpected("Type in applyUpdateNoPtsCheck()");
	}
}

void Updates::applyUpdates(
		const MTPUpdates &updates,
		uint64 sentMessageRandomId) {
	const auto randomId = sentMessageRandomId;

	switch (updates.type()) {
	case mtpc_updates: {
		auto &d = updates.c_updates();
		if (d.vseq().v) {
			if (d.vseq().v <= _updatesSeq) {
				return;
			}
			if (d.vseq().v > _updatesSeq + 1) {
				_bySeqUpdates.emplace(d.vseq().v, updates);
				_bySeqTimer.callOnce(PtsWaiter::kWaitForSkippedTimeout);
				return;
			}
		}

		session().data().processUsers(d.vusers());
		session().data().processChats(d.vchats());
		feedUpdateVector(d.vupdates());

		setState(0, d.vdate().v, _updatesQts, d.vseq().v);
	} break;

	case mtpc_updatesCombined: {
		auto &d = updates.c_updatesCombined();
		if (d.vseq_start().v) {
			if (d.vseq_start().v <= _updatesSeq) {
				return;
			}
			if (d.vseq_start().v > _updatesSeq + 1) {
				_bySeqUpdates.emplace(d.vseq_start().v, updates);
				_bySeqTimer.callOnce(PtsWaiter::kWaitForSkippedTimeout);
				return;
			}
		}

		session().data().processUsers(d.vusers());
		session().data().processChats(d.vchats());
		feedUpdateVector(d.vupdates());

		setState(0, d.vdate().v, _updatesQts, d.vseq().v);
	} break;

	case mtpc_updateShort: {
		auto &d = updates.c_updateShort();
		feedUpdate(d.vupdate());

		setState(0, d.vdate().v, _updatesQts, _updatesSeq);
	} break;

	case mtpc_updateShortMessage: {
		auto &d = updates.c_updateShortMessage();
		if (!session().data().userLoaded(d.vuser_id())) {
			MTP_LOG(0, ("getDifference "
				"{ good - getting user for updateShortMessage }%1"
			).arg(_session->mtp().isTestMode() ? " TESTMODE" : ""));
			return getDifference();
		}
		_session->data().fillMessagePeers(d);
		if (updateAndApply(d.vpts().v, d.vpts_count().v, updates)) {
			// Update date as well.
			setState(0, d.vdate().v, _updatesQts, _updatesSeq);
		}
	} break;

	case mtpc_updateShortChatMessage: {
		auto &d = updates.c_updateShortChatMessage();
		const auto chat = session().data().chatLoaded(d.vchat_id());
		if (!chat) {
			MTP_LOG(0, ("getDifference "
				"{ good - getting chat for updateShortChatMessage }%1"
			).arg(_session->mtp().isTestMode() ? " TESTMODE" : ""));
			return getDifference();
		}
		_session->data().fillMessagePeers(d);
		if (updateAndApply(d.vpts().v, d.vpts_count().v, updates)) {
			// Update date as well.
			setState(0, d.vdate().v, _updatesQts, _updatesSeq);
		}
	} break;

	case mtpc_updateShortSentMessage: {
		auto &d = updates.c_updateShortSentMessage();
		if (!IsServerMsgId(d.vid().v)) {
			LOG(("API Error: Bad msgId got from server: %1").arg(d.vid().v));
		} else if (randomId) {
			auto &owner = session().data();
			const auto sent = owner.messageSentData(randomId);
			const auto lookupMessage = [&] {
				return sent.peerId
					? owner.message(sent.peerId, d.vid().v)
					: nullptr;
			};
			if (const auto id = owner.messageIdByRandomId(randomId)) {
				const auto local = owner.message(id);
				if (local && local->isScheduled()) {
					session().scheduledMessages().sendNowSimpleMessage(
						d,
						local);
				}
			}
			const auto wasAlready = (lookupMessage() != nullptr);
			feedUpdate(MTP_updateMessageID(d.vid(), MTP_long(randomId))); // ignore real date
			if (const auto item = lookupMessage()) {
				_session->data().fillMessagePeers(item->fullId(), d);
				item->applySentMessage(sent.text, d, wasAlready);
			}
		}

		if (updateAndApply(d.vpts().v, d.vpts_count().v, updates)) {
			// Update date as well.
			setState(0, d.vdate().v, _updatesQts, _updatesSeq);
		}
	} break;

	case mtpc_updatesTooLong: {
		MTP_LOG(0, ("getDifference "
			"{ good - updatesTooLong received }%1"
			).arg(_session->mtp().isTestMode() ? " TESTMODE" : ""));
		return getDifference();
	} break;
	}
	session().data().sendHistoryChangeNotifications();
}

void Updates::feedUpdate(const MTPUpdate &update) {
	switch (update.type()) {

	// New messages.
	case mtpc_updateNewMessage: {
		auto &d = update.c_updateNewMessage();
		if (!requestingDifference()) {
			const auto peerId = PeerFromMessage(d.vmessage());
			const auto peer = session().data().peerLoaded(peerId);
			if (peerId && !peer) {
				MTP_LOG(0, ("getDifference "
					"{ good - getting peer for updateNewMessage }%1"
				).arg(_session->mtp().isTestMode() ? " TESTMODE" : ""));
				return getDifference();
			}
		}
		updateAndApply(d.vpts().v, d.vpts_count().v, update);
	} break;

	case mtpc_updateNewChannelMessage: {
		auto &d = update.c_updateNewChannelMessage();
		auto channel = session().data().channelLoaded(peerToChannel(PeerFromMessage(d.vmessage())));
		{
			// Todo delete.
			const auto messageId = IdFromMessage(d.vmessage());
			if (const auto history = channel ? session().data().historyLoaded(channel) : nullptr) {
				if (history->isUnknownMessageDeleted(messageId)) {
					LOG(("Unknown message deleted detected for channel %1, message %2")
						.arg(channel->id.value & PeerId::kChatTypeMask)
						.arg(messageId.bare));
				}
			}
		}
		if (!requestingDifference() && !channel) {
			MTP_LOG(0, ("getDifference "
				"{ good - after not all data loaded in updateNewChannelMessage }%1"
				).arg(_session->mtp().isTestMode() ? " TESTMODE" : ""));
			if (!_byMinChannelTimer.isActive()) { // getDifference after timeout
				_byMinChannelTimer.callOnce(PtsWaiter::kWaitForSkippedTimeout);
			}
			return;
		}
		if (channel && !_handlingChannelDifference) {
			if (channel->ptsRequesting()) { // skip global updates while getting channel difference
				MTP_LOG(0, ("Skipping new channel message because getting the difference."));
				return;
			}
			channel->ptsUpdateAndApply(d.vpts().v, d.vpts_count().v, update);
		} else {
			applyUpdateNoPtsCheck(update);
		}
	} break;

	case mtpc_updateMessageID: {
		const auto &d = update.c_updateMessageID();
		const auto randomId = d.vrandom_id().v;
		if (const auto id = session().data().messageIdByRandomId(randomId)) {
			const auto newId = d.vid().v;
			auto &owner = session().data();
			if (const auto local = owner.message(id)) {
				if (local->isScheduled()) {
					session().scheduledMessages().apply(d, local);
				} else if (local->isBusinessShortcut()) {
					session().data().shortcutMessages().apply(d, local);
				} else {
					const auto existing = session().data().message(
						id.peer,
						newId);
					if (existing && !local->mainView()) {
						const auto history = local->history();
						local->destroy();
						history->requestChatListMessage();
					} else {
						if (existing) {
							existing->destroy();
						} else {
							// Not the server-side date, but close enough.
							session().topPeers().increment(
								local->history()->peer,
								local->date());
						}
						local->setRealId(newId);
						if (const auto topic = local->topic()) {
							topic->applyMaybeLast(local);
						}
						if (const auto sublist = local->savedSublist()) {
							sublist->applyMaybeLast(local);
						}
					}
				}
			} else {
				owner.histories().checkTopicCreated(id, newId);
			}
			session().data().unregisterMessageRandomId(randomId);
		} else {
			Core::App().calls().handleUpdate(&session(), update);
		}
		session().data().unregisterMessageSentData(randomId);
	} break;

	// Message contents being read.
	case mtpc_updateReadMessagesContents: {
		auto &d = update.c_updateReadMessagesContents();
		updateAndApply(d.vpts().v, d.vpts_count().v, update);
	} break;

	case mtpc_updateChannelReadMessagesContents: {
		auto &d = update.c_updateChannelReadMessagesContents();
		auto channel = session().data().channelLoaded(d.vchannel_id());
		if (!channel) {
			if (!_byMinChannelTimer.isActive()) {
				// getDifference after timeout.
				_byMinChannelTimer.callOnce(PtsWaiter::kWaitForSkippedTimeout);
			}
			return;
		}
		auto unknownReadIds = base::flat_set<MsgId>();
		for (const auto &msgId : d.vmessages().v) {
			if (auto item = session().data().message(channel->id, msgId.v)) {
				if (item->isUnreadMedia() || item->isUnreadMention()) {
					item->markMediaAndMentionRead();
					session().data().requestItemRepaint(item);
				}
			} else {
				// Perhaps it was an unread mention!
				unknownReadIds.insert(msgId.v);
			}
		}
		session().api().unreadThings().mediaAndMentionsRead(
			unknownReadIds,
			channel);
	} break;

	// Edited messages.
	case mtpc_updateEditMessage: {
		auto &d = update.c_updateEditMessage();
		updateAndApply(d.vpts().v, d.vpts_count().v, update);
	} break;

	case mtpc_updateEditChannelMessage: {
		auto &d = update.c_updateEditChannelMessage();
		auto channel = session().data().channelLoaded(peerToChannel(PeerFromMessage(d.vmessage())));

		if (channel && !_handlingChannelDifference) {
			if (channel->ptsRequesting()) { // skip global updates while getting channel difference
				MTP_LOG(0, ("Skipping channel message edit because getting the difference."));
				return;
			} else {
				channel->ptsUpdateAndApply(d.vpts().v, d.vpts_count().v, update);
			}
		} else {
			applyUpdateNoPtsCheck(update);
		}
	} break;

	case mtpc_updatePinnedChannelMessages: {
		auto &d = update.c_updatePinnedChannelMessages();
		auto channel = session().data().channelLoaded(d.vchannel_id());

		if (channel && !_handlingChannelDifference) {
			if (channel->ptsRequesting()) { // skip global updates while getting channel difference
				MTP_LOG(0, ("Skipping pinned channel messages because getting the difference."));
				return;
			} else {
				channel->ptsUpdateAndApply(d.vpts().v, d.vpts_count().v, update);
			}
		} else {
			applyUpdateNoPtsCheck(update);
		}
	} break;

	case mtpc_updateMessageReactions: {
		const auto &d = update.c_updateMessageReactions();
		const auto peer = peerFromMTP(d.vpeer());
		if (const auto history = session().data().historyLoaded(peer)) {
			const auto item = session().data().message(
				peer,
				d.vmsg_id().v);
			if (item) {
				item->updateReactions(&d.vreactions());
			} else {
				const auto hasUnreadReaction = Data::Reactions::HasUnread(
					d.vreactions());
				if (hasUnreadReaction || history->unreadReactions().has()) {
					// The unread reactions count could change.
					history->owner().histories().requestDialogEntry(history);
				}
				if (hasUnreadReaction) {
					history->unreadReactions().checkAdd(d.vmsg_id().v);
				}
			}
		}
	} break;

	case mtpc_updateMessageExtendedMedia: {
		const auto &d = update.c_updateMessageExtendedMedia();
		const auto peerId = peerFromMTP(d.vpeer());
		const auto msgId = d.vmsg_id().v;
		if (const auto item = session().data().message(peerId, msgId)) {
			item->applyEdition(d.vextended_media().v);
		}
	} break;

	// Messages being read.
	case mtpc_updateReadHistoryInbox: {
		auto &d = update.c_updateReadHistoryInbox();
		updateAndApply(d.vpts().v, d.vpts_count().v, update);
	} break;

	case mtpc_updateReadHistoryOutbox: {
		auto &d = update.c_updateReadHistoryOutbox();
		updateAndApply(d.vpts().v, d.vpts_count().v, update);
	} break;

	case mtpc_updateReadChannelInbox: {
		const auto &d = update.c_updateReadChannelInbox();
		const auto peer = peerFromChannel(d.vchannel_id().v);
		if (const auto history = session().data().historyLoaded(peer)) {
			history->applyInboxReadUpdate(
				d.vfolder_id().value_or_empty(),
				d.vmax_id().v,
				d.vstill_unread_count().v,
				d.vpts().v);
		}
	} break;

	case mtpc_updateReadChannelOutbox: {
		const auto &d = update.c_updateReadChannelOutbox();
		const auto peer = peerFromChannel(d.vchannel_id().v);
		if (const auto history = session().data().historyLoaded(peer)) {
			history->outboxRead(d.vmax_id().v);
			if (!requestingDifference()) {
				if (const auto user = history->peer->asUser()) {
					user->madeAction(base::unixtime::now());
				}
			}
		}
	} break;

	case mtpc_updateDialogUnreadMark: {
		const auto &data = update.c_updateDialogUnreadMark();
		data.vpeer().match(
		[&](const MTPDdialogPeer &dialog) {
			const auto id = peerFromMTP(dialog.vpeer());
			if (const auto history = session().data().historyLoaded(id)) {
				history->setUnreadMark(data.is_unread());
			}
		}, [](const MTPDdialogPeerFolder &dialog) {
		});
	} break;

	case mtpc_updateFolderPeers: {
		const auto &data = update.c_updateFolderPeers();

		updateAndApply(data.vpts().v, data.vpts_count().v, update);
	} break;

	case mtpc_updateDialogFilter:
	case mtpc_updateDialogFilterOrder:
	case mtpc_updateDialogFilters: {
		session().data().chatsFilters().apply(update);
	} break;

	// Deleted messages.
	case mtpc_updateDeleteMessages: {
		auto &d = update.c_updateDeleteMessages();

		updateAndApply(d.vpts().v, d.vpts_count().v, update);
	} break;

	case mtpc_updateDeleteChannelMessages: {
		auto &d = update.c_updateDeleteChannelMessages();
		auto channel = session().data().channelLoaded(d.vchannel_id());

		if (channel && !_handlingChannelDifference) {
			if (channel->ptsRequesting()) { // skip global updates while getting channel difference
				MTP_LOG(0, ("Skipping delete channel messages because getting the difference."));
				return;
			}
			channel->ptsUpdateAndApply(d.vpts().v, d.vpts_count().v, update);
		} else {
			applyUpdateNoPtsCheck(update);
		}
	} break;

	case mtpc_updateNewScheduledMessage: {
		const auto &d = update.c_updateNewScheduledMessage();
		session().scheduledMessages().apply(d);
	} break;

	case mtpc_updateDeleteScheduledMessages: {
		const auto &d = update.c_updateDeleteScheduledMessages();
		session().scheduledMessages().apply(d);
	} break;

	case mtpc_updateQuickReplies: {
		const auto &d = update.c_updateQuickReplies();
		session().data().shortcutMessages().apply(d);
	} break;

	case mtpc_updateNewQuickReply: {
		const auto &d = update.c_updateNewQuickReply();
		session().data().shortcutMessages().apply(d);
	} break;

	case mtpc_updateDeleteQuickReply: {
		const auto &d = update.c_updateDeleteQuickReply();
		session().data().shortcutMessages().apply(d);
	} break;

	case mtpc_updateQuickReplyMessage: {
		const auto &d = update.c_updateQuickReplyMessage();
		session().data().shortcutMessages().apply(d);
	} break;

	case mtpc_updateDeleteQuickReplyMessages: {
		const auto &d = update.c_updateDeleteQuickReplyMessages();
		session().data().shortcutMessages().apply(d);
	} break;

	case mtpc_updateWebPage: {
		auto &d = update.c_updateWebPage();

		// Update web page anyway.
		session().data().processWebpage(d.vwebpage());
		session().data().sendWebPageGamePollTodoListNotifications();

		updateAndApply(d.vpts().v, d.vpts_count().v, update);
	} break;

	case mtpc_updateChannelWebPage: {
		auto &d = update.c_updateChannelWebPage();

		// Update web page anyway.
		session().data().processWebpage(d.vwebpage());
		session().data().sendWebPageGamePollTodoListNotifications();

		auto channel = session().data().channelLoaded(d.vchannel_id());
		if (channel && !_handlingChannelDifference) {
			if (channel->ptsRequesting()) { // skip global updates while getting channel difference
				MTP_LOG(0, ("Skipping channel web page update because getting the difference."));
				return;
			} else {
				channel->ptsUpdateAndApply(d.vpts().v, d.vpts_count().v, update);
			}
		} else {
			applyUpdateNoPtsCheck(update);
		}
	} break;

	case mtpc_updateMessagePoll: {
		session().data().applyUpdate(update.c_updateMessagePoll());
	} break;

	case mtpc_updateUserTyping: {
		auto &d = update.c_updateUserTyping();
		handleSendActionUpdate(
			peerFromUser(d.vuser_id()),
			d.vtop_msg_id().value_or_empty(),
			peerFromUser(d.vuser_id()),
			d.vaction());
	} break;

	case mtpc_updateChatUserTyping: {
		auto &d = update.c_updateChatUserTyping();
		handleSendActionUpdate(
			peerFromChat(d.vchat_id()),
			0,
			peerFromMTP(d.vfrom_id()),
			d.vaction());
	} break;

	case mtpc_updateChannelUserTyping: {
		const auto &d = update.c_updateChannelUserTyping();
		handleSendActionUpdate(
			peerFromChannel(d.vchannel_id()),
			d.vtop_msg_id().value_or_empty(),
			peerFromMTP(d.vfrom_id()),
			d.vaction());
	} break;

	case mtpc_updateChatParticipants: {
		session().data().applyUpdate(update.c_updateChatParticipants());
	} break;

	case mtpc_updateChatParticipantAdd: {
		session().data().applyUpdate(update.c_updateChatParticipantAdd());
	} break;

	case mtpc_updateChatParticipantDelete: {
		session().data().applyUpdate(update.c_updateChatParticipantDelete());
	} break;

	case mtpc_updateChatParticipantAdmin: {
		session().data().applyUpdate(update.c_updateChatParticipantAdmin());
	} break;

	case mtpc_updateChatDefaultBannedRights: {
		session().data().applyUpdate(update.c_updateChatDefaultBannedRights());
	} break;

	case mtpc_updateUserStatus: {
		auto &d = update.c_updateUserStatus();
		if (const auto user = session().data().userLoaded(d.vuser_id())) {
			const auto now = LastseenFromMTP(d.vstatus(), user->lastseen());
			if (user->updateLastseen(now)) {
				session().changes().peerUpdated(
					user,
					Data::PeerUpdate::Flag::OnlineStatus);
			}
		}
		if (UserId(d.vuser_id()) == session().userId()) {
			if (d.vstatus().type() == mtpc_userStatusOffline
				|| d.vstatus().type() == mtpc_userStatusEmpty) {
				updateOnline(Core::App().lastNonIdleTime(), true);
				if (d.vstatus().type() == mtpc_userStatusOffline) {
					cSetOtherOnline(
						d.vstatus().c_userStatusOffline().vwas_online().v);
				}
			} else if (d.vstatus().type() == mtpc_userStatusOnline) {
				cSetOtherOnline(
					d.vstatus().c_userStatusOnline().vexpires().v);
			}
		}
	} break;

	case mtpc_updateUserName: {
		const auto &d = update.c_updateUserName();
		if (const auto user = session().data().userLoaded(d.vuser_id())) {
			const auto contact = user->isContact();
			const auto first = contact
				? user->firstName
				: qs(d.vfirst_name());
			const auto last = contact ? user->lastName : qs(d.vlast_name());
			// #TODO usernames
			const auto username = d.vusernames().v.isEmpty()
				? QString()
				: qs(d.vusernames().v.front().data().vusername());
			user->setName(
				TextUtilities::SingleLine(first),
				TextUtilities::SingleLine(last),
				user->nameOrPhone,
				TextUtilities::SingleLine(username));
			user->setUsernames(Api::Usernames::FromTL(d.vusernames()));
		}
	} break;

	case mtpc_updateUser: {
		auto &d = update.c_updateUser();
		if (const auto user = session().data().userLoaded(d.vuser_id())) {
			if (user->wasFullUpdated()) {
				user->updateFullForced();
			}
		}
	} break;

	case mtpc_updatePeerSettings: {
		const auto &d = update.c_updatePeerSettings();
		const auto peerId = peerFromMTP(d.vpeer());
		if (const auto peer = session().data().peerLoaded(peerId)) {
			peer->setBarSettings(d.vsettings());
		}
	} break;

	case mtpc_updateNotifySettings: {
		auto &d = update.c_updateNotifySettings();
		session().data().notifySettings().apply(
			d.vpeer(),
			d.vnotify_settings());
	} break;

	case mtpc_updateDcOptions: {
		auto &d = update.c_updateDcOptions();
		session().mtp().dcOptions().addFromList(d.vdc_options());
	} break;

	case mtpc_updateConfig: {
		session().mtp().requestConfig();
		session().promoSuggestions().invalidate();
	} break;

	case mtpc_updateUserPhone: {
		const auto &d = update.c_updateUserPhone();
		if (const auto user = session().data().userLoaded(d.vuser_id())) {
			const auto newPhone = qs(d.vphone());
			if (newPhone != user->phone()) {
				user->setPhone(newPhone);
				user->setName(
					user->firstName,
					user->lastName,
					((user->isContact()
						|| user->isServiceUser()
						|| user->isSelf()
						|| user->phone().isEmpty())
						? QString()
						: Ui::FormatPhone(user->phone())),
					user->username());

				session().changes().peerUpdated(
					user,
					Data::PeerUpdate::Flag::PhoneNumber);
			}
		}
	} break;

	case mtpc_updatePeerHistoryTTL: {
		const auto &d = update.c_updatePeerHistoryTTL();
		const auto peerId = peerFromMTP(d.vpeer());
		if (const auto peer = session().data().peerLoaded(peerId)) {
			peer->setMessagesTTL(d.vttl_period().value_or_empty());
		}
	} break;

	case mtpc_updateNewEncryptedMessage: {
		const auto &d = update.c_updateNewEncryptedMessage();
		const auto &message = d.vmessage();

		switch (message.type()) {
		case mtpc_encryptedMessageService: {
			const auto &m = message.c_encryptedMessageService();
			const auto chatId = int64(m.vchat_id().v);
			const auto payload = m.vbytes().v;

			LOG(("1335 SecretChat: updateNewEncryptedMessage -> encryptedMessageService "
				"chat_id=%1 random_id=%2 date=%3 bytes_size=%4 qts=%5")
				.arg(chatId)
				.arg(QString::number(static_cast<qulonglong>(m.vrandom_id().v)))
				.arg(m.vdate().v)
				.arg(payload.size())
				.arg(d.vqts().v));

			Data::SecretChats::Manager(&session()).HandleEncryptedMessage(
				chatId,
				payload,
				"encryptedMessageService");
		} break;

		case mtpc_encryptedMessage: {
			const auto &m = message.c_encryptedMessage();
			const auto chatId = int64(m.vchat_id().v);
			const auto payload = m.vbytes().v;

			LOG(("1335 SecretChat: updateNewEncryptedMessage -> encryptedMessage "
				"chat_id=%1 random_id=%2 date=%3 bytes_size=%4 qts=%5 has_file=%6")
				.arg(chatId)
				.arg(QString::number(static_cast<qulonglong>(m.vrandom_id().v)))
				.arg(m.vdate().v)
				.arg(payload.size())
				.arg(d.vqts().v)
				.arg(m.vfile().type() != mtpc_encryptedFileEmpty ? 1 : 0));

			Data::SecretChats::Manager(&session()).HandleEncryptedMessage(
				chatId,
				payload,
				"encryptedMessage");
		} break;

		default:
			LOG(("1335 SecretChat: updateNewEncryptedMessage -> unknown message.type=%1")
				.arg(int(message.type())));
		break;
		}
	} break;

	case mtpc_updateEncryptedChatTyping: {
		LOG(("1336 SecretChat: updateEncryptedChatTyping received."));
	} break;

	case mtpc_updateEncryption: {
		const auto &d = update.c_updateEncryption();
		const auto &chat = d.vchat();

		switch (chat.type()) {
		case mtpc_encryptedChatRequested: {
			const auto &c = chat.c_encryptedChatRequested();

			// Copy request fields before async work.
			const auto requestedChatId = c.vid().v;
			const auto requestedAccessHash = c.vaccess_hash().v;
			const auto requestedAdminId = c.vadmin_id().v;
			const auto requestedParticipantId = c.vparticipant_id().v;
			const auto requestedGA = c.vg_a().v;

			LOG(("1337 SecretChat: updateEncryption -> encryptedChatRequested "
				"id=%1 access_hash=%2 admin_id=%3 participant_id=%4 date=%5 g_a_size=%6")
				.arg(requestedChatId)
				.arg(requestedAccessHash)
				.arg(requestedAdminId)
				.arg(requestedParticipantId)
				.arg(c.vdate().v)
				.arg(requestedGA.size()));

			// Fetch DH config, generate g_b, compute shared auth_key, then accept.
			session().api().request(MTPmessages_GetDhConfig(
				MTP_int(0),
				MTP_int(MTP::ModExpFirst::kRandomPowerSize)
			)).done([=](const MTPmessages_DhConfig &result) {
				result.match([&](const MTPDmessages_dhConfig &data) {
					LOG(("1337 SecretChat: getDhConfig -> dhConfig "
						"g=%1 p_size=%2 version=%3 random_size=%4")
						.arg(data.vg().v)
						.arg(data.vp().v.size())
						.arg(data.vversion().v)
						.arg(data.vrandom().v.size()));

					auto primeBytes = bytes::make_vector(data.vp().v);
					if (!MTP::IsPrimeAndGood(primeBytes, data.vg().v)) {
						LOG(("1337 SecretChat: bad p/g in dhConfig"));
						return;
					}

					const auto modexp = MTP::CreateModExp(
						data.vg().v,
						primeBytes,
						bytes::make_span(data.vrandom().v));

					if (modexp.modexp.empty()) {
						LOG(("1337 SecretChat: CreateModExp failed"));
						return;
					}

					const auto computedAuthKey = MTP::CreateAuthKey(
						bytes::make_span(requestedGA),
						modexp.randomPower,
						primeBytes);

					if (computedAuthKey.empty()) {
						LOG(("1337 SecretChat: CreateAuthKey failed"));
						return;
					}

					MTP::AuthKey::Data paddedAuthKey = {};
					MTP::AuthKey::FillData(paddedAuthKey, computedAuthKey);

					const auto authKeySha1 = openssl::Sha1(bytes::make_span(paddedAuthKey));

					uint64 keyFingerprint = 0;
					std::memcpy(&keyFingerprint, authKeySha1.data() + 12, 8);

					LOG(("1337 SecretChat: computed incoming accept values "
						"g_b_size=%1 shared_key_size=%2 padded_key_size=%3 key_fingerprint=%4")
						.arg(modexp.modexp.size())
						.arg(computedAuthKey.size())
						.arg(int(MTP::AuthKey::kSize))
						.arg(QString::number(static_cast<qulonglong>(keyFingerprint))));

					session().api().request(MTPmessages_AcceptEncryption(
						MTP_inputEncryptedChat(
							MTP_int(requestedChatId),
							MTP_long(requestedAccessHash)
						),
						MTP_bytes(modexp.modexp),
						MTP_long(static_cast<uint64>(keyFingerprint))
					)).done([=](const MTPEncryptedChat &result) {
						switch (result.type()) {
						case mtpc_encryptedChat: {
							const auto &accepted = result.c_encryptedChat();

							LOG(("1337 SecretChat: acceptEncryption done -> encryptedChat "
								"id=%1 access_hash=%2 admin_id=%3 participant_id=%4 date=%5 key_fingerprint=%6 g_a_or_b_size=%7")
								.arg(accepted.vid().v)
								.arg(accepted.vaccess_hash().v)
								.arg(accepted.vadmin_id().v)
								.arg(accepted.vparticipant_id().v)
								.arg(accepted.vdate().v)
								.arg(accepted.vkey_fingerprint().v)
								.arg(accepted.vg_a_or_b().v.size()));

							Data::SecretChats::SecretChatState state;
							state.chat_id = accepted.vid().v;
							state.access_hash = static_cast<uint64>(accepted.vaccess_hash().v);
							state.admin_id = static_cast<uint64>(accepted.vadmin_id().v);
							state.participant_id = static_cast<uint64>(accepted.vparticipant_id().v);
							state.is_creator = false; // The remote side requested this chat; we are the acceptor, not the originator.
							state.key_fingerprint = keyFingerprint;
							state.auth_key = paddedAuthKey;

							if (!Data::SecretChats::Manager(&session()).SaveState(state)) {
								LOG(("1337 SecretChat: state save failed after acceptEncryption"));
							}
						} break;

						case mtpc_encryptedChatDiscarded: {
							const auto &discarded = result.c_encryptedChatDiscarded();
							LOG(("1337 SecretChat: acceptEncryption done -> encryptedChatDiscarded id=%1")
								.arg(discarded.vid().v));
						} break;

						case mtpc_encryptedChatWaiting: {
							const auto &waiting = result.c_encryptedChatWaiting();
							LOG(("1337 SecretChat: acceptEncryption done -> encryptedChatWaiting id=%1")
								.arg(waiting.vid().v));
						} break;

						default:
							LOG(("1337 SecretChat: acceptEncryption done -> unexpected result.type=%1")
								.arg(int(result.type())));
						break;
						}
					}).fail([=] {
						LOG(("1337 SecretChat: acceptEncryption failed"));
					}).send();

				}, [&](const MTPDmessages_dhConfigNotModified &data) {
					LOG(("1337 SecretChat: getDhConfig -> dhConfigNotModified "
						"random_size=%1")
						.arg(data.vrandom().v.size()));
				});
			}).fail([=] {
				LOG(("1337 SecretChat: getDhConfig failed"));
			}).send();

		} break;

		case mtpc_encryptedChatDiscarded: {
			const auto &c = chat.c_encryptedChatDiscarded();
			LOG(("1337 SecretChat: updateEncryption -> encryptedChatDiscarded id=%1")
				.arg(c.vid().v));
		} break;

		case mtpc_encryptedChatWaiting: {
			const auto &c = chat.c_encryptedChatWaiting();
			LOG(("1337 SecretChat: updateEncryption -> encryptedChatWaiting "
				"id=%1 access_hash=%2 admin_id=%3 participant_id=%4 date=%5")
				.arg(c.vid().v)
				.arg(c.vaccess_hash().v)
				.arg(c.vadmin_id().v)
				.arg(c.vparticipant_id().v)
				.arg(c.vdate().v));
		} break;

		case mtpc_encryptedChat: {
			const auto &c = chat.c_encryptedChat();
			LOG(("1337 SecretChat: updateEncryption -> encryptedChat "
				"id=%1 access_hash=%2 admin_id=%3 participant_id=%4 date=%5 key_fingerprint=%6 g_a_or_b_size=%7")
				.arg(c.vid().v)
				.arg(c.vaccess_hash().v)
				.arg(c.vadmin_id().v)
				.arg(c.vparticipant_id().v)
				.arg(c.vdate().v)
				.arg(c.vkey_fingerprint().v)
				.arg(c.vg_a_or_b().v.size()));
		} break;

		case mtpc_encryptedChatEmpty: {
			const auto &c = chat.c_encryptedChatEmpty();
			LOG(("1337 SecretChat: updateEncryption -> encryptedChatEmpty id=%1")
				.arg(c.vid().v));
		} break;

		default:
			LOG(("1337 SecretChat: updateEncryption -> unknown chat.type=%1")
				.arg(int(chat.type())));
		break;
		}
	} break;

	case mtpc_updateEncryptedMessagesRead: {
		LOG(("1338 SecretChat: updateEncryptedMessagesRead received."));
	} break;


	case mtpc_updatePhoneCall:
	case mtpc_updatePhoneCallSignalingData:
	case mtpc_updateGroupCallParticipants:
	case mtpc_updateGroupCallChainBlocks:
	case mtpc_updateGroupCallConnection:
	case mtpc_updateGroupCall:
	case mtpc_updateGroupCallMessage:
	case mtpc_updateGroupCallEncryptedMessage:
	case mtpc_updateDeleteGroupCallMessages: {
		Core::App().calls().handleUpdate(&session(), update);
	} break;

	case mtpc_updatePeerBlocked: {
		const auto &d = update.c_updatePeerBlocked();
		if (const auto peer = session().data().peerLoaded(peerFromMTP(d.vpeer_id()))) {
			peer->setIsBlocked(d.is_blocked());
		}
	} break;

	case mtpc_updatePeerWallpaper: {
		const auto &d = update.c_updatePeerWallpaper();
		if (const auto peer = session().data().peerLoaded(peerFromMTP(d.vpeer()))) {
			if (const auto paper = d.vwallpaper()) {
				peer->setWallPaper(
					Data::WallPaper::Create(&session(), *paper),
					d.is_wallpaper_overridden());
			} else {
				peer->setWallPaper({});
			}
		}
	} break;

	case mtpc_updateBotCommands: {
		const auto &d = update.c_updateBotCommands();
		if (const auto peer = session().data().peerLoaded(peerFromMTP(d.vpeer()))) {
			const auto botId = UserId(d.vbot_id().v);
			const auto commands = Data::BotCommands{
				.userId = UserId(d.vbot_id().v),
				.commands = ranges::views::all(
					d.vcommands().v
				) | ranges::views::transform(
					Data::BotCommandFromTL
				) | ranges::to_vector,
			};

			if (const auto user = peer->asUser()) {
				if (user->isBot() && user->id == peerFromUser(botId)) {
					const auto equal = ranges::equal(
						user->botInfo->commands,
						commands.commands);
					user->botInfo->commands = commands.commands;
					if (!equal) {
						session().data().botCommandsChanged(user);
					}
				}
			} else if (const auto chat = peer->asChat()) {
				chat->setBotCommands({ commands });
			} else if (const auto megagroup = peer->asMegagroup()) {
				if (megagroup->mgInfo->setBotCommands({ commands })) {
					session().data().botCommandsChanged(megagroup);
				}
			}
		}
	} break;

	case mtpc_updateAttachMenuBots: {
		session().attachWebView().requestBots();
	} break;

	case mtpc_updateWebViewResultSent: {
		const auto &d = update.c_updateWebViewResultSent();
		session().data().webViewResultSent({ .queryId = d.vquery_id().v });
	} break;

	case mtpc_updateBotMenuButton: {
		const auto &d = update.c_updateBotMenuButton();
		if (const auto bot = session().data().userLoaded(d.vbot_id())) {
			if (const auto info = bot->botInfo.get(); info && info->inited) {
				if (Data::ApplyBotMenuButton(info, &d.vbutton())) {
					session().data().botCommandsChanged(bot);
				}
			}
		}
	} break;

	case mtpc_updatePendingJoinRequests: {
		const auto &d = update.c_updatePendingJoinRequests();
		if (const auto peer = session().data().peerLoaded(peerFromMTP(d.vpeer()))) {
			const auto count = d.vrequests_pending().v;
			const auto &requesters = d.vrecent_requesters().v;
			if (const auto chat = peer->asChat()) {
				chat->setPendingRequestsCount(count, requesters);
			} else if (const auto channel = peer->asChannel()) {
				channel->setPendingRequestsCount(count, requesters);
			}
		}
	} break;

	case mtpc_updateNewAuthorization: {
		session().api().authorizations().apply(update);
	} break;

	case mtpc_updateServiceNotification: {
		const auto &d = update.c_updateServiceNotification();
		const auto text = TextWithEntities {
			qs(d.vmessage()),
			Api::EntitiesFromMTP(&session(), d.ventities().v)
		};
		if (IsForceLogoutNotification(d)) {
			Core::App().forceLogOut(&session().account(), text);
		} else if (IsWithdrawalNotification(d)) {
			return;
		} else if (d.is_popup()) {
			const auto &windows = session().windows();
			if (!windows.empty()) {
				windows.front()->window().show(Ui::MakeInformBox(text));
			}
		} else {
			session().data().serviceNotification(
				text,
				d.vmedia(),
				d.is_invert_media());
			session().api().authorizations().reload();
		}
	} break;

	case mtpc_updatePrivacy: {
		auto &d = update.c_updatePrivacy();
		const auto allChatsLoaded = [&](const MTPVector<MTPlong> &ids) {
			for (const auto &chatId : ids.v) {
				if (!session().data().chatLoaded(chatId)
					&& !session().data().channelLoaded(chatId)) {
					return false;
				}
			}
			return true;
		};
		const auto allLoaded = [&] {
			for (const auto &rule : d.vrules().v) {
				const auto loaded = rule.match([&](
					const MTPDprivacyValueAllowChatParticipants & data) {
					return allChatsLoaded(data.vchats());
				}, [&](const MTPDprivacyValueDisallowChatParticipants & data) {
					return allChatsLoaded(data.vchats());
				}, [](auto &&) { return true; });
				if (!loaded) {
					return false;
				}
			}
			return true;
		};
		session().api().userPrivacy().apply(
			d.vkey().type(),
			d.vrules(),
			allLoaded());
	} break;

	case mtpc_updatePinnedDialogs: {
		const auto &d = update.c_updatePinnedDialogs();
		const auto folderId = d.vfolder_id().value_or_empty();
		const auto loaded = !folderId
			|| (session().data().folderLoaded(folderId) != nullptr);
		const auto folder = folderId
			? session().data().folder(folderId).get()
			: nullptr;
		const auto done = [&] {
			const auto list = d.vorder();
			if (!list) {
				return false;
			}
			const auto &order = list->v;
			const auto notLoaded = [&](const MTPDialogPeer &peer) {
				return peer.match([&](const MTPDdialogPeer &data) {
					return !session().data().historyLoaded(
						peerFromMTP(data.vpeer()));
				}, [&](const MTPDdialogPeerFolder &data) {
					if (folderId) {
						LOG(("API Error: "
							"updatePinnedDialogs has nested folders."));
						return true;
					}
					return !session().data().folderLoaded(data.vfolder_id().v);
				});
			};
			if (!ranges::none_of(order, notLoaded)) {
				return false;
			}
			session().data().applyPinnedChats(folder, order);
			return true;
		}();
		if (!done) {
			session().api().requestPinnedDialogs(folder);
		}
		if (!loaded) {
			session().data().histories().requestDialogEntry(folder);
		}
	} break;

	case mtpc_updateDialogPinned: {
		const auto &d = update.c_updateDialogPinned();
		const auto folderId = d.vfolder_id().value_or_empty();
		const auto folder = folderId
			? session().data().folder(folderId).get()
			: nullptr;
		const auto done = d.vpeer().match([&](const MTPDdialogPeer &data) {
			const auto id = peerFromMTP(data.vpeer());
			if (const auto history = session().data().historyLoaded(id)) {
				history->applyPinnedUpdate(d);
				return true;
			}
			DEBUG_LOG(("API Error: "
				"pinned chat not loaded for peer %1, folder: %2"
				).arg(id.value
				).arg(folderId
				));
			return false;
		}, [&](const MTPDdialogPeerFolder &data) {
			if (folderId != 0) {
				DEBUG_LOG(("API Error: Nested folders updateDialogPinned."));
				return false;
			}
			const auto id = data.vfolder_id().v;
			if (const auto folder = session().data().folderLoaded(id)) {
				folder->applyPinnedUpdate(d);
				return true;
			}
			DEBUG_LOG(("API Error: "
				"pinned folder not loaded for folderId %1, folder: %2"
				).arg(id
				).arg(folderId
				));
			return false;
		});
		if (!done) {
			session().api().requestPinnedDialogs(folder);
		}
	} break;

	case mtpc_updatePinnedSavedDialogs: {
		session().data().savedMessages().apply(
			update.c_updatePinnedSavedDialogs());
	} break;

	case mtpc_updateSavedDialogPinned: {
		session().data().savedMessages().apply(
			update.c_updateSavedDialogPinned());
	} break;

	case mtpc_updateChannel: {
		auto &d = update.c_updateChannel();
		if (const auto channel = session().data().channelLoaded(d.vchannel_id())) {
			channel->inviter = UserId(0);
			channel->inviteViaRequest = false;
			if (channel->amIn()) {
				if (channel->isMegagroup()
					&& !channel->amCreator()
					&& !channel->hasAdminRights()) {
					channel->updateFullForced();
				}
				const auto history = channel->owner().history(channel);
				history->requestChatListMessage();
				if (!history->folderKnown()
					|| (!history->unreadCountKnown()
						&& !history->isForum())) {
					history->owner().histories().requestDialogEntry(history);
				}
				if (!channel->amCreator()) {
					session().api().chatParticipants().requestSelf(channel);
				}
			}
		}
	} break;

	case mtpc_updateChannelTooLong: {
		const auto &d = update.c_updateChannelTooLong();
		if (const auto channel = session().data().channelLoaded(d.vchannel_id())) {
			const auto pts = d.vpts();
			if (!pts || channel->pts() < pts->v) {
				getChannelDifference(channel);
			}
		}
	} break;

	case mtpc_updateChannelMessageViews: {
		const auto &d = update.c_updateChannelMessageViews();
		const auto peerId = peerFromChannel(d.vchannel_id());
		if (const auto item = session().data().message(peerId, d.vid().v)) {
			if (item->changeViewsCount(d.vviews().v)) {
				session().data().notifyItemDataChange(item);
			}
		}
	} break;

	case mtpc_updateChannelMessageForwards: {
		const auto &d = update.c_updateChannelMessageForwards();
		const auto peerId = peerFromChannel(d.vchannel_id());
		if (const auto item = session().data().message(peerId, d.vid().v)) {
			item->setForwardsCount(d.vforwards().v);
		}
	} break;

	case mtpc_updateReadChannelDiscussionInbox: {
		const auto &d = update.c_updateReadChannelDiscussionInbox();
		const auto id = FullMsgId(
			peerFromChannel(d.vchannel_id()),
			d.vtop_msg_id().v);
		const auto readTillId = d.vread_max_id().v;
		session().data().updateRepliesReadTill({ id, readTillId, false });
		const auto item = session().data().message(id);
		if (item) {
			item->setCommentsInboxReadTill(readTillId);
			if (const auto post = item->lookupDiscussionPostOriginal()) {
				post->setCommentsInboxReadTill(readTillId);
			}
		}
		if (const auto broadcastId = d.vbroadcast_id()) {
			if (const auto post = session().data().message(
					peerFromChannel(*broadcastId),
					d.vbroadcast_post()->v)) {
				post->setCommentsInboxReadTill(readTillId);
			}
		}
	} break;

	case mtpc_updateReadChannelDiscussionOutbox: {
		const auto &d = update.c_updateReadChannelDiscussionOutbox();
		const auto id = FullMsgId(
			peerFromChannel(d.vchannel_id()),
			d.vtop_msg_id().v);
		const auto readTillId = d.vread_max_id().v;
		session().data().updateRepliesReadTill({ id, readTillId, true });
	} break;

	case mtpc_updateReadMonoForumInbox: {
		const auto &d = update.c_updateReadMonoForumInbox();
		const auto parentChatId = ChannelId(d.vchannel_id());
		const auto sublistPeerId = peerFromMTP(d.vsaved_peer_id());
		const auto readTillId = d.vread_max_id().v;
		session().data().updateSublistReadTill({
			parentChatId,
			sublistPeerId,
			readTillId,
			false,
		});
	} break;

	case mtpc_updateReadMonoForumOutbox: {
		const auto &d = update.c_updateReadMonoForumOutbox();
		const auto parentChatId = ChannelId(d.vchannel_id());
		const auto sublistPeerId = peerFromMTP(d.vsaved_peer_id());
		const auto readTillId = d.vread_max_id().v;
		session().data().updateSublistReadTill({
			parentChatId,
			sublistPeerId,
			readTillId,
			true,
		});
	} break;

	case mtpc_updateChannelAvailableMessages: {
		auto &d = update.c_updateChannelAvailableMessages();
		if (const auto channel = session().data().channelLoaded(d.vchannel_id())) {
			channel->setAvailableMinId(d.vavailable_min_id().v);
			if (const auto history = session().data().historyLoaded(channel)) {
				history->clearUpTill(d.vavailable_min_id().v);
			}
		}
	} break;

	case mtpc_updatePinnedForumTopic: {
		const auto &d = update.c_updatePinnedForumTopic();
		const auto peerId = peerFromMTP(d.vpeer());
		if (const auto peer = session().data().peerLoaded(peerId)) {
			const auto rootId = d.vtopic_id().v;
			if (const auto topic = peer->forumTopicFor(rootId)) {
				session().data().setChatPinned(topic, 0, d.is_pinned());
			} else if (const auto forum = peer->forum()) {
				forum->requestTopic(rootId);
			}
		}
	} break;

	case mtpc_updatePinnedForumTopics: {
		const auto &d = update.c_updatePinnedForumTopics();
		const auto peerId = peerFromMTP(d.vpeer());
		if (const auto peer = session().data().peerLoaded(peerId)) {
			if (const auto forum = peer->forum()) {
				const auto done = [&] {
					const auto list = d.vorder();
					if (!list) {
						return false;
					}
					const auto &order = list->v;
					const auto notLoaded = [&](const MTPint &topicId) {
						return !forum->topicFor(topicId.v);
					};
					if (!ranges::none_of(order, notLoaded)) {
						return false;
					}
					session().data().applyPinnedTopics(forum, order);
					return true;
				}();
				if (!done) {
					forum->reloadTopics();
				}
			}
		}
	} break;

	case mtpc_updateChannelViewForumAsMessages: {
		const auto &d = update.c_updateChannelViewForumAsMessages();
		const auto id = ChannelId(d.vchannel_id());
		if (const auto channel = session().data().channelLoaded(id)) {
			channel->setViewAsMessagesFlag(mtpIsTrue(d.venabled()));
		}
	} break;

	// Pinned message.
	case mtpc_updatePinnedMessages: {
		const auto &d = update.c_updatePinnedMessages();
		updateAndApply(d.vpts().v, d.vpts_count().v, update);
	} break;

	////// Cloud sticker sets
	case mtpc_updateNewStickerSet: {
		const auto &d = update.c_updateNewStickerSet();
		d.vstickerset().match([&](const MTPDmessages_stickerSet &data) {
			session().data().stickers().newSetReceived(data);
		}, [](const MTPDmessages_stickerSetNotModified &) {
			LOG(("API Error: Unexpected messages.stickerSetNotModified."));
		});
	} break;

	case mtpc_updateStickerSetsOrder: {
		auto &d = update.c_updateStickerSetsOrder();
		auto &stickers = session().data().stickers();
		const auto isEmoji = d.is_emojis();
		const auto isMasks = d.is_masks();
		const auto &order = d.vorder().v;
		const auto &sets = stickers.sets();
		Data::StickersSetsOrder result;
		for (const auto &item : order) {
			if (sets.find(item.v) == sets.cend()) {
				break;
			}
			result.push_back(item.v);
		}
		const auto localSize = isEmoji
			? stickers.emojiSetsOrder().size()
			: isMasks
			? stickers.maskSetsOrder().size()
			: stickers.setsOrder().size();
		if ((result.size() != localSize) || (result.size() != order.size())) {
			if (isEmoji) {
				stickers.setLastEmojiUpdate(0);
				session().api().updateCustomEmoji();
			} else if (isMasks) {
				stickers.setLastMasksUpdate(0);
				session().api().updateMasks();
			} else {
				stickers.setLastUpdate(0);
				session().api().updateStickers();
			}
		} else {
			if (isEmoji) {
				stickers.emojiSetsOrderRef() = std::move(result);
				session().local().writeInstalledCustomEmoji();
			} else if (isMasks) {
				stickers.maskSetsOrderRef() = std::move(result);
				session().local().writeInstalledMasks();
			} else {
				stickers.setsOrderRef() = std::move(result);
				session().local().writeInstalledStickers();
			}
			stickers.notifyUpdated(isEmoji
				? Data::StickersType::Emoji
				: isMasks
				? Data::StickersType::Masks
				: Data::StickersType::Stickers);
		}
	} break;

	case mtpc_updateMoveStickerSetToTop: {
		const auto &d = update.c_updateMoveStickerSetToTop();
		auto &stickers = session().data().stickers();
		const auto isEmoji = d.is_emojis();
		const auto setId = d.vstickerset().v;
		auto &order = isEmoji
			? stickers.emojiSetsOrderRef()
			: stickers.setsOrderRef();
		const auto i = ranges::find(order, setId);
		if (i == order.end()) {
			if (isEmoji) {
				stickers.setLastEmojiUpdate(0);
				session().api().updateCustomEmoji();
			} else {
				stickers.setLastUpdate(0);
				session().api().updateStickers();
			}
		} else if (i != order.begin()) {
			std::rotate(order.begin(), i, i + 1);
			if (isEmoji) {
				session().local().writeInstalledCustomEmoji();
			} else {
				session().local().writeInstalledStickers();
			}
			stickers.notifyUpdated(isEmoji
				? Data::StickersType::Emoji
				: Data::StickersType::Stickers);
		}
	} break;

	case mtpc_updateStickerSets: {
		const auto &d = update.c_updateStickerSets();
		if (d.is_emojis()) {
			session().data().stickers().setLastEmojiUpdate(0);
			session().api().updateCustomEmoji();
		} else if (d.is_masks()) {
			session().data().stickers().setLastMasksUpdate(0);
			session().api().updateMasks();
		} else {
			session().data().stickers().setLastUpdate(0);
			session().api().updateStickers();
		}
	} break;

	case mtpc_updateRecentStickers: {
		session().data().stickers().setLastRecentUpdate(0);
		session().api().updateStickers();
	} break;

	case mtpc_updateFavedStickers: {
		session().data().stickers().setLastFavedUpdate(0);
		session().api().updateStickers();
	} break;

	case mtpc_updateReadFeaturedStickers: {
		// We read some of the featured stickers, perhaps not all of them.
		// Here we don't know what featured sticker sets were read, so we
		// request all of them once again.
		session().data().stickers().setLastFeaturedUpdate(0);
		session().api().updateStickers();
	} break;

	case mtpc_updateReadFeaturedEmojiStickers: {
		// We don't track read status of them for now.
	} break;

	case mtpc_updateUserEmojiStatus: {
		const auto &d = update.c_updateUserEmojiStatus();
		if (const auto user = session().data().userLoaded(d.vuser_id())) {
			user->setEmojiStatus(d.vemoji_status());
		}
	} break;

	case mtpc_updateRecentEmojiStatuses: {
		session().data().emojiStatuses().refreshRecentDelayed();
	} break;

	case mtpc_updateRecentReactions: {
		session().data().reactions().refreshRecentDelayed();
	} break;

	case mtpc_updateSavedReactionTags: {
		session().data().reactions().refreshMyTagsDelayed();
	} break;

	////// Cloud saved GIFs
	case mtpc_updateSavedGifs: {
		session().data().stickers().setLastSavedGifsUpdate(0);
		session().api().updateSavedGifs();
	} break;

	////// Cloud drafts
	case mtpc_updateDraftMessage: {
		const auto &data = update.c_updateDraftMessage();
		const auto peerId = peerFromMTP(data.vpeer());
		const auto topicRootId = data.vtop_msg_id().value_or_empty();
		const auto monoforumPeerId = data.vsaved_peer_id()
			? peerFromMTP(*data.vsaved_peer_id())
			: PeerId();
		data.vdraft().match([&](const MTPDdraftMessage &data) {
			Data::ApplyPeerCloudDraft(
				&session(),
				peerId,
				topicRootId,
				monoforumPeerId,
				data);
		}, [&](const MTPDdraftMessageEmpty &data) {
			Data::ClearPeerCloudDraft(
				&session(),
				peerId,
				topicRootId,
				monoforumPeerId,
				data.vdate().value_or_empty());
		});
	} break;

	////// Cloud langpacks
	case mtpc_updateLangPack: {
		const auto &data = update.c_updateLangPack();
		Lang::CurrentCloudManager().applyLangPackDifference(data.vdifference());
	} break;

	case mtpc_updateLangPackTooLong: {
		const auto &data = update.c_updateLangPackTooLong();
		const auto code = qs(data.vlang_code());
		if (!code.isEmpty()) {
			Lang::CurrentCloudManager().requestLangPackDifference(code);
		}
	} break;

	////// Cloud themes
	case mtpc_updateTheme: {
		const auto &data = update.c_updateTheme();
		session().data().cloudThemes().applyUpdate(data.vtheme());
	} break;

	case mtpc_updateSavedRingtones: {
		session().api().ringtones().applyUpdate();
	} break;

	case mtpc_updateTranscribedAudio: {
		const auto &data = update.c_updateTranscribedAudio();
		_session->api().transcribes().apply(data);
	} break;

	case mtpc_updateStory: {
		_session->data().stories().apply(update.c_updateStory());
	} break;

	case mtpc_updateReadStories: {
		_session->data().stories().apply(update.c_updateReadStories());
	} break;

	case mtpc_updateStoriesStealthMode: {
		const auto &data = update.c_updateStoriesStealthMode();
		_session->data().stories().apply(data.vstealth_mode());
	} break;

	case mtpc_updateStarsBalance: {
		const auto &data = update.c_updateStarsBalance();
		_session->credits().apply(data);
	} break;

	case mtpc_updatePaidReactionPrivacy: {
		const auto &data = update.c_updatePaidReactionPrivacy();
		_session->api().globalPrivacy().updatePaidReactionShownPeer(
			Api::ParsePaidReactionShownPeer(_session, data.vprivate()));
	} break;

	case mtpc_updateStarGiftAuctionState: {
		const auto &data = update.c_updateStarGiftAuctionState();
		_session->giftAuctions().apply(data);
	} break;

	case mtpc_updateStarGiftAuctionUserState: {
		const auto &data = update.c_updateStarGiftAuctionUserState();
		_session->giftAuctions().apply(data);
	} break;

	case mtpc_updateEmojiGameInfo: {
		const auto &data = update.c_updateEmojiGameInfo();
		_session->diceStickersPacks().apply(data);
	} break;
	}
}

bool IsWithdrawalNotification(const MTPDupdateServiceNotification &data) {
	return qs(data.vtype()).startsWith(u"API_WITHDRAWAL_FEATURE_DISABLED_"_q);
}

} // namespace Api
