#include "data/secret/secret_chat_state.h"

namespace Data::SecretChats {

QString FormatUint64(uint64_t value) {
	return QString::number(static_cast<qulonglong>(value));
}

QString FormatUint32Hex(uint32_t value) {
	return QString("0x%1").arg(value, 8, 16, QLatin1Char('0'));
}

} // namespace Data::SecretChats