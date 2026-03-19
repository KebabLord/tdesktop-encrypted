#pragma once

#include <QString>
#include <QVector>

#include <cstdint>
#include <variant>

namespace Data::SecretChats {

struct SecretChatDescriptor {
	int64_t chatId = 0;
	uint64_t accessHash = 0;
	uint64_t adminId = 0;
	uint64_t participantId = 0;
	bool isCreator = false;
};

struct SecretParsedEntity {
	uint32_t constructor = 0;
	int32_t offset = 0;
	int32_t length = 0;
};

struct SecretParsedTextMessage {
	int64_t chatId = 0;
	uint64_t randomId = 0;
	uint32_t flags = 0;
	int32_t ttl = 0;
	QString text;
	QVector<SecretParsedEntity> entities;
};

struct SecretParsedServiceMessage {
	int64_t chatId = 0;
	uint64_t randomId = 0;
	uint32_t actionConstructor = 0;
};

struct SecretParsedUnsupportedMessage {
	int64_t chatId = 0;
	uint32_t constructor = 0;
	QString description;
};

using SecretParsedMessage = std::variant<
	SecretParsedTextMessage,
	SecretParsedServiceMessage,
	SecretParsedUnsupportedMessage>;

} // namespace Data::SecretChats