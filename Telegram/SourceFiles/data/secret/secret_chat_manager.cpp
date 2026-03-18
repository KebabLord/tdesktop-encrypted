#include "data/secret/secret_chat_manager.h"
#include "data/secret/secret_chat_crypto.h"
#include "data/secret/secret_chat_parser.h"
#include "data/secret/secret_chat_storage.h"
#include "data/secret/secret_chat_types.h"

#include "logs.h"
#include "main/main_session.h"
#include "mtproto/mtproto_config.h"
#include "mtproto/mtproto_dh_utils.h"
#include "apiwrap.h"

#include "base/openssl_help.h"

namespace Data::SecretChats {

SecretChatManager::SecretChatManager(not_null<Main::Session*> session)
: _session(session) {
	RefreshKnownChats();
}

void SecretChatManager::RefreshKnownChats() {
	_knownChats = LoadAllSecretChats();
}

void SecretChatManager::HandleEncryptedMessage(
		int64_t chatId,
		const QByteArray &payload,
		const char *tag) {
	const auto state = LoadState(chatId);
	if (!state.has_value()) {
		LOG(("1335 SecretChat: no state found for %1 chat_id=%2")
			.arg(QString::fromLatin1(tag))
			.arg(chatId));
		return;
	}

	if (payload.size() < 24) {
		LOG(("1335 SecretChat: payload too short for %1 chat_id=%2 size=%3")
			.arg(QString::fromLatin1(tag))
			.arg(chatId)
			.arg(payload.size()));
		return;
	}

	uint64_t receivedFingerprint = 0;
	std::memcpy(&receivedFingerprint, payload.constData(), 8);

	const auto msgKeyHex = payload.mid(8, 16).toHex();
	const auto encryptedSize = payload.size() - 24;

	LOG(("1335 SecretChat: %1 envelope chat_id=%2 stored_fingerprint=%3 received_fingerprint=%4 msg_key=%5 encrypted_size=%6")
		.arg(QString::fromLatin1(tag))
		.arg(chatId)
		.arg(FormatUint64(state->key_fingerprint))
		.arg(FormatUint64(receivedFingerprint))
		.arg(QString::fromLatin1(msgKeyHex))
		.arg(encryptedSize));

	if (receivedFingerprint != state->key_fingerprint) {
		LOG(("1335 SecretChat: fingerprint mismatch for %1 chat_id=%2")
			.arg(QString::fromLatin1(tag))
			.arg(chatId));
		return;
	}

	const auto decrypted = DecryptSecretChatPayloadMtproto2(*state, payload);
	if (!decrypted.has_value()) {
		LOG(("1335 SecretChat: failed to decrypt %1 chat_id=%2")
			.arg(QString::fromLatin1(tag))
			.arg(chatId));
		return;
	}

	const auto parsed = ParseDecryptedSecretChatPayload(chatId, *decrypted, tag);
	if (!parsed.has_value()) {
		LOG(("1335 SecretChat: failed to parse %1 chat_id=%2")
			.arg(QString::fromLatin1(tag))
			.arg(chatId));
		return;
	}

	StoreParsedMessage(chatId, *parsed);
}

void SecretChatManager::HandleEncryptedChatRequested(
		int32 requestedChatId,
		uint64 requestedAccessHash,
		uint64 requestedAdminId,
		uint64 requestedParticipantId,
		const QByteArray &requestedGA,
		int32 requestDate) {
	LOG(("1337 SecretChat: updateEncryption -> encryptedChatRequested "
		"id=%1 access_hash=%2 admin_id=%3 participant_id=%4 date=%5 g_a_size=%6")
		.arg(requestedChatId)
		.arg(requestedAccessHash)
		.arg(requestedAdminId)
		.arg(requestedParticipantId)
		.arg(requestDate)
		.arg(requestedGA.size()));

	_session->api().request(MTPmessages_GetDhConfig(
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
				.arg(FormatUint64(keyFingerprint)));

			_session->api().request(MTPmessages_AcceptEncryption(
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

					SecretChatState state;
					state.chat_id = accepted.vid().v;
					state.access_hash = static_cast<uint64>(accepted.vaccess_hash().v);
					state.admin_id = static_cast<uint64>(accepted.vadmin_id().v);
					state.participant_id = static_cast<uint64>(accepted.vparticipant_id().v);
					state.is_creator = false; // The remote side requested this chat; we are the acceptor.
					state.key_fingerprint = keyFingerprint;
					state.auth_key = paddedAuthKey;

					if (!SaveState(state)) {
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
			LOG(("1337 SecretChat: getDhConfig -> dhConfigNotModified random_size=%1")
				.arg(data.vrandom().v.size()));
		});
	}).fail([=] {
		LOG(("1337 SecretChat: getDhConfig failed"));
	}).send();
}

void SecretChatManager::LogEncryptionChat(const MTPEncryptedChat &chat, const char *tag) const {
	switch (chat.type()) {
	case mtpc_encryptedChatRequested: {
		const auto &c = chat.c_encryptedChatRequested();
		LOG(("1337 SecretChat: %1 -> encryptedChatRequested "
			"id=%2 access_hash=%3 admin_id=%4 participant_id=%5 date=%6 g_a_size=%7")
			.arg(QString::fromLatin1(tag))
			.arg(c.vid().v)
			.arg(c.vaccess_hash().v)
			.arg(c.vadmin_id().v)
			.arg(c.vparticipant_id().v)
			.arg(c.vdate().v)
			.arg(c.vg_a().v.size()));
	} break;

	case mtpc_encryptedChatDiscarded: {
		const auto &c = chat.c_encryptedChatDiscarded();
		LOG(("1337 SecretChat: %1 -> encryptedChatDiscarded id=%2")
			.arg(QString::fromLatin1(tag))
			.arg(c.vid().v));
	} break;

	case mtpc_encryptedChatWaiting: {
		const auto &c = chat.c_encryptedChatWaiting();
		LOG(("1337 SecretChat: %1 -> encryptedChatWaiting "
			"id=%2 access_hash=%3 admin_id=%4 participant_id=%5 date=%6")
			.arg(QString::fromLatin1(tag))
			.arg(c.vid().v)
			.arg(c.vaccess_hash().v)
			.arg(c.vadmin_id().v)
			.arg(c.vparticipant_id().v)
			.arg(c.vdate().v));
	} break;

	case mtpc_encryptedChat: {
		const auto &c = chat.c_encryptedChat();
		LOG(("1337 SecretChat: %1 -> encryptedChat "
			"id=%2 access_hash=%3 admin_id=%4 participant_id=%5 date=%6 key_fingerprint=%7 g_a_or_b_size=%8")
			.arg(QString::fromLatin1(tag))
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
		LOG(("1337 SecretChat: %1 -> encryptedChatEmpty id=%2")
			.arg(QString::fromLatin1(tag))
			.arg(c.vid().v));
	} break;

	default:
		LOG(("1337 SecretChat: %1 -> unknown chat.type=%2")
			.arg(QString::fromLatin1(tag))
			.arg(int(chat.type())));
		break;
	}
}

bool SecretChatManager::SaveState(const SecretChatState &state) const {
	const auto saved = SaveSecretChatState(state);
	if (saved) {
		const_cast<SecretChatManager*>(this)->RefreshKnownChats();
	}
	return saved;
}

const QVector<SecretChatDescriptor> &SecretChatManager::KnownChats() const {
	return _knownChats;
}

std::optional<SecretChatState> SecretChatManager::LoadState(int64_t chatId) const {
	return LoadSecretChatState(chatId);
}

SecretChatManager &Manager(not_null<Main::Session*> session) {
	static auto manager = std::make_unique<SecretChatManager>(session);
	return *manager;
}

void SecretChatManager::StoreParsedMessage(
		int64_t chatId,
		SecretParsedMessage message) {
	auto &list = _messages[chatId];
	list.push_back(std::move(message));
	LOG(("1335 SecretChat: stored parsed message chat_id=%1 total=%2")
		.arg(chatId)
		.arg(list.size()));
}

const QVector<SecretParsedMessage> &SecretChatManager::Messages(int64_t chatId) const {
	static const QVector<SecretParsedMessage> kEmpty;
	const auto i = _messages.find(chatId);
	return (i == _messages.end()) ? kEmpty : i.value();
}

} // namespace Data::SecretChats