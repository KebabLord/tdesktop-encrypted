#include "data/secret/secret_chat_storage.h"

#include "base/algorithm.h"
#include "logs.h"

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>

namespace Data::SecretChats {
namespace {

constexpr auto kSecretChatsDir = "/home/owo/Github/tdesktop/tmp/secret_chats";

QString SecretChatStatePath(int64_t chatId) {
	return QString("%1/%2.json").arg(kSecretChatsDir).arg(chatId);
}

QString AuthKeyToHex(const MTP::AuthKey::Data &authKey) {
	const auto raw = QByteArray(
		reinterpret_cast<const char*>(authKey.data()),
		int(authKey.size()));
	return QString::fromLatin1(raw.toHex());
}

bool AuthKeyFromHex(const QString &hex, MTP::AuthKey::Data &out) {
	const auto raw = QByteArray::fromHex(hex.toLatin1());
	if (raw.size() != int(MTP::AuthKey::kSize)) {
		return false;
	}
	std::memcpy(out.data(), raw.constData(), size_t(raw.size()));
	return true;
}

} // namespace

bool SaveSecretChatState(const SecretChatState &state) {
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

std::optional<SecretChatState> LoadSecretChatState(int64_t chatId) {
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
		.arg(FormatUint64(state.key_fingerprint))
		.arg(state.is_creator ? 1 : 0));
	return state;
}

} // namespace Data::SecretChats