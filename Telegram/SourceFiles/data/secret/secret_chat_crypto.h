#pragma once

#include "data/secret/secret_chat_state.h"

#include <QByteArray>
#include <optional>

namespace Data::SecretChats {

std::optional<QByteArray> DecryptSecretChatPayloadMtproto2(
	const SecretChatState &state,
	const QByteArray &payload);

std::optional<QByteArray> EncryptSecretChatPayloadMtproto2(
	const SecretChatState &state,
	const QByteArray &body);

} // namespace Data::SecretChats