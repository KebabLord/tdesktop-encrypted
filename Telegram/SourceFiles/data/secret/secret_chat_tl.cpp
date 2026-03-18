#include "data/secret/secret_chat_tl.h"
#include "data/secret/secret_chat_state.h"

namespace Data::SecretChats {

uint32_t ReadLE32(const char *data) {
	uint32_t value = 0;
	std::memcpy(&value, data, sizeof(value));
	return value;
}

uint64_t ReadLE64(const char *data) {
	uint64_t value = 0;
	std::memcpy(&value, data, sizeof(value));
	return value;
}

QString BytesToHex(const QByteArray &data, int maxBytes) {
	const auto slice = (maxBytes >= 0) ? data.left(maxBytes) : data;
	return QString::fromLatin1(slice.toHex());
}

bool SecretTlReader::CanRead(int bytes) const {
	return (bytes >= 0) && (offset >= 0) && (offset + bytes <= limit);
}

std::optional<uint32_t> SecretTlReader::ReadUInt32() {
	if (!CanRead(4)) {
		return std::nullopt;
	}
	const auto value = ReadLE32(data.constData() + offset);
	offset += 4;
	return value;
}

std::optional<int32_t> SecretTlReader::ReadInt32() {
	const auto value = ReadUInt32();
	if (!value.has_value()) {
		return std::nullopt;
	}
	return static_cast<int32_t>(*value);
}

std::optional<uint64_t> SecretTlReader::ReadUInt64() {
	if (!CanRead(8)) {
		return std::nullopt;
	}
	const auto value = ReadLE64(data.constData() + offset);
	offset += 8;
	return value;
}

std::optional<QByteArray> SecretTlReader::ReadTLBytes() {
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

std::optional<QString> SecretTlReader::ReadTLString() {
	const auto bytes = ReadTLBytes();
	if (!bytes.has_value()) {
		return std::nullopt;
	}
	return QString::fromUtf8(bytes->constData(), bytes->size());
}

QString SecretMessageEntityName(uint32_t constructor) {
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

QString SecretMediaConstructorName(uint32_t constructor) {
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

} // namespace Data::SecretChats