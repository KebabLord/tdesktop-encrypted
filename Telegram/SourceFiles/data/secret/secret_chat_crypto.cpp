#include "data/secret/secret_chat_crypto.h"
#include "data/secret/secret_chat_tl.h"
#include "logs.h"
#include "mtproto/mtproto_auth_key.h"
#include "mtproto/mtproto_config.h"

#include "base/openssl_help.h"
#include "base/random.h"

#include <array>
#include <openssl/sha.h>

namespace Data::SecretChats {

namespace {

// Build the MTProto2 secret-chat AES key and IV for a specific direction.
void PrepareSecretChatAes(
		const SecretChatState &state,
		const MTPint128 &msgKey,
		int x,
		MTPint256 &aesKey,
		MTPint256 &aesIV) {
	bytes::array<32> sha256_a, sha256_b;

	bytes::array<16 + 36> data_a;
	std::memcpy(data_a.data(), &msgKey, 16);
	std::memcpy(
		data_a.data() + 16,
		reinterpret_cast<const uchar*>(state.auth_key.data()) + x,
		36);
	openssl::Sha256To(sha256_a, data_a);

	bytes::array<36 + 16> data_b;
	std::memcpy(
		data_b.data(),
		reinterpret_cast<const uchar*>(state.auth_key.data()) + 40 + x,
		36);
	std::memcpy(data_b.data() + 36, &msgKey, 16);
	openssl::Sha256To(sha256_b, data_b);

	auto key = reinterpret_cast<uchar*>(&aesKey);
	auto iv = reinterpret_cast<uchar*>(&aesIV);

	std::memcpy(key, sha256_a.data(), 8);
	std::memcpy(key + 8, sha256_b.data() + 8, 16);
	std::memcpy(key + 24, sha256_a.data() + 24, 8);

	std::memcpy(iv, sha256_b.data(), 8);
	std::memcpy(iv + 8, sha256_a.data() + 8, 16);
	std::memcpy(iv + 24, sha256_b.data() + 24, 8);
}

} // namespace

std::optional<QByteArray> DecryptSecretChatPayloadMtproto2(
		const SecretChatState &state,
		const QByteArray &payload) {
	if (payload.size() < 24) {
		LOG(("1335 SecretChat: payload too short for decryption size=%1")
			.arg(payload.size()));
		return std::nullopt;
	}

	const auto encryptedSize = payload.size() - 24;
	if ((encryptedSize <= 0) || (encryptedSize % 16 != 0)) {
		LOG(("1335 SecretChat: encrypted payload size is invalid size=%1")
			.arg(encryptedSize));
		return std::nullopt;
	}

	MTPint128 msgKey;
	std::memcpy(&msgKey, payload.constData() + 8, sizeof(msgKey));

	MTPint256 aesKey, aesIV;
	const int x = state.is_creator ? 8 : 0;
	PrepareSecretChatAes(state, msgKey, x, aesKey, aesIV);

	auto decrypted = QByteArray(encryptedSize, Qt::Uninitialized);
	MTP::aesIgeDecryptRaw(
		payload.constData() + 24,
		decrypted.data(),
		encryptedSize,
		&aesKey,
		&aesIV);

	std::array<uchar, 32> sha256Buffer = { { 0 } };
	SHA256_CTX msgKeyLargeContext;
	SHA256_Init(&msgKeyLargeContext);
	SHA256_Update(
		&msgKeyLargeContext,
		reinterpret_cast<const uchar*>(state.auth_key.data()) + 88 + x,
		32);
	SHA256_Update(
		&msgKeyLargeContext,
		decrypted.constData(),
		size_t(encryptedSize));
	SHA256_Final(sha256Buffer.data(), &msgKeyLargeContext);

	constexpr auto kMsgKeyShift = 8U;
	if (std::memcmp(&msgKey, sha256Buffer.data() + kMsgKeyShift, sizeof(msgKey)) != 0) {
		LOG(("1335 SecretChat: MTProto2 msg_key verification failed x=%1")
			.arg(x));
		return std::nullopt;
	}

	if (decrypted.size() < 4) {
		LOG(("1335 SecretChat: decrypted payload too small after verify size=%1")
			.arg(decrypted.size()));
		return std::nullopt;
	}

	const auto bodyLength = int(ReadLE32(decrypted.constData()));
	const auto usedBytes = 4 + bodyLength;
	if (bodyLength < 0 || usedBytes > decrypted.size()) {
		LOG(("1335 SecretChat: invalid decrypted body length body_length=%1 decrypted_size=%2")
			.arg(bodyLength)
			.arg(decrypted.size()));
		return std::nullopt;
	}

	const auto paddingBytes = decrypted.size() - usedBytes;
	if (paddingBytes < kMinMtproto2Padding || paddingBytes > kMaxMtproto2Padding) {
		LOG(("1335 SecretChat: invalid MTProto2 padding body_length=%1 padding=%2 decrypted_size=%3")
			.arg(bodyLength)
			.arg(paddingBytes)
			.arg(decrypted.size()));
		return std::nullopt;
	}

	LOG(("1335 SecretChat: MTProto2 msg_key verification passed x=%1 body_length=%2 padding=%3")
		.arg(x)
		.arg(bodyLength)
		.arg(paddingBytes));

	return decrypted;
}

// Encrypt an outbound secret-chat payload using the MTProto2 secret format.
std::optional<QByteArray> EncryptSecretChatPayloadMtproto2(
		const SecretChatState &state,
		const QByteArray &body) {
	if (body.isEmpty()) {
		LOG(("1335 SecretChat: outbound body is empty"));
		return std::nullopt;
	}

	auto plaintext = QByteArray();
	plaintext.reserve(4 + body.size() + 32);
	AppendInt32(plaintext, body.size());
	plaintext.append(body);

	auto padding = kMinMtproto2Padding;
	while ((plaintext.size() + padding) % 16 != 0) {
		++padding;
	}
	if (padding > kMaxMtproto2Padding) {
		LOG(("1335 SecretChat: outbound padding exceeds limit body_size=%1 padding=%2")
			.arg(body.size())
			.arg(padding));
		return std::nullopt;
	}
	for (auto i = 0; i != padding; ++i) {
		plaintext.push_back(char(base::RandomValue<uchar>()));
	}

	const auto x = state.is_creator ? 0 : 8;
	std::array<uchar, 32> sha256Buffer = { { 0 } };
	SHA256_CTX msgKeyLargeContext;
	SHA256_Init(&msgKeyLargeContext);
	SHA256_Update(
		&msgKeyLargeContext,
		reinterpret_cast<const uchar*>(state.auth_key.data()) + 88 + x,
		32);
	SHA256_Update(
		&msgKeyLargeContext,
		plaintext.constData(),
		size_t(plaintext.size()));
	SHA256_Final(sha256Buffer.data(), &msgKeyLargeContext);

	MTPint128 msgKey = {};
	std::memcpy(&msgKey, sha256Buffer.data() + 8, sizeof(msgKey));

	MTPint256 aesKey, aesIV;
	PrepareSecretChatAes(state, msgKey, x, aesKey, aesIV);

	auto encrypted = QByteArray(plaintext.size(), Qt::Uninitialized);
	MTP::aesIgeEncryptRaw(
		plaintext.constData(),
		encrypted.data(),
		plaintext.size(),
		&aesKey,
		&aesIV);

	auto result = QByteArray();
	result.reserve(8 + 16 + encrypted.size());
	result.append(
		reinterpret_cast<const char*>(&state.key_fingerprint),
		sizeof(state.key_fingerprint));
	result.append(reinterpret_cast<const char*>(&msgKey), sizeof(msgKey));
	result.append(encrypted);

	LOG(("1335 SecretChat: encrypted outbound payload x=%1 body_length=%2 padding=%3 encrypted_size=%4")
		.arg(x)
		.arg(body.size())
		.arg(padding)
		.arg(encrypted.size()));

	return result;
}

} // namespace Data::SecretChats