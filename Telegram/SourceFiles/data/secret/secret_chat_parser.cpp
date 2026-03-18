#include "data/secret/secret_chat_parser.h"

#include "data/secret/secret_chat_state.h"
#include "data/secret/secret_chat_tl.h"
#include "logs.h"

namespace Data::SecretChats {
namespace {

bool ParseSecretMessageEntities(
		int64_t chatId,
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

} // namespace

void ParseDecryptedSecretChatPayload(
		int64_t chatId,
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
		} else {
			LOG(("1335 SecretChat: %1 media chat_id=%2 none")
				.arg(QString::fromLatin1(tag))
				.arg(chatId));
		}

		if (*flags & (1 << 7)) {
			if (!ParseSecretMessageEntities(chatId, tag, reader, *messageText)) {
				return;
			}
		}

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

} // namespace Data::SecretChats