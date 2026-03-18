#include "data/secret/secret_chat_crypto.h"
#include "data/secret/secret_chat_tl.h"
#include "logs.h"
#include "mtproto/mtproto_auth_key.h"
#include "mtproto/mtproto_config.h"

#include "base/openssl_help.h"

#include <array>
#include <openssl/sha.h>

namespace Data::SecretChats {

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

	{
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

} // namespace Data::SecretChats