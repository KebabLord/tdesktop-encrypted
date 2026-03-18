#pragma once

#include "data/secret/secret_chat_state.h"

#include <optional>

namespace Data::SecretChats {

bool SaveSecretChatState(const SecretChatState &state);
std::optional<SecretChatState> LoadSecretChatState(int64_t chatId);

} // namespace Data::SecretChats