#pragma once

#include "data/secret/secret_chat_types.h"

#include <QByteArray>
#include <optional>
#include <cstdint>

namespace Data::SecretChats {

std::optional<SecretParsedMessage> ParseDecryptedSecretChatPayload(
	int64_t chatId,
	const QByteArray &decrypted,
	const char *tag);

} // namespace Data::SecretChats