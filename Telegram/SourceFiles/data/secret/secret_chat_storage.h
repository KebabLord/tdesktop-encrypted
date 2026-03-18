#pragma once

#include "data/secret/secret_chat_state.h"
#include "data/secret/secret_chat_types.h"

#include <QVector>
#include <optional>

namespace Data::SecretChats {

bool SaveSecretChatState(const SecretChatState &state);
std::optional<SecretChatState> LoadSecretChatState(int64_t chatId);
QVector<SecretChatDescriptor> LoadAllSecretChats();

} // namespace Data::SecretChats