#pragma once

#include "data/secret/secret_chat_state.h"
#include "main/main_session.h"

#include <optional>

namespace Main {
class Session;
} // namespace Main

namespace Data::SecretChats {

class SecretChatManager {
public:
	explicit SecretChatManager(not_null<Main::Session*> session);

	void HandleEncryptedMessage(
		int64_t chatId,
		const QByteArray &payload,
		const char *tag);

	void HandleEncryptedChatRequested(
		int32 requestedChatId,
		uint64 requestedAccessHash,
		uint64 requestedAdminId,
		uint64 requestedParticipantId,
		const QByteArray &requestedGA,
		int32 requestDate);

	void LogEncryptionChat(const MTPEncryptedChat &chat, const char *tag) const;

	bool SaveState(const SecretChatState &state) const;
	std::optional<SecretChatState> LoadState(int64_t chatId) const;

private:
	not_null<Main::Session*> _session;
};

SecretChatManager &Manager(not_null<Main::Session*> session);

} // namespace Data::SecretChats