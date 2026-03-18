#pragma once

#include <QByteArray>
#include <cstdint>

namespace Data::SecretChats {

void ParseDecryptedSecretChatPayload(
	int64_t chatId,
	const QByteArray &decrypted,
	const char *tag);

} // namespace Data::SecretChats