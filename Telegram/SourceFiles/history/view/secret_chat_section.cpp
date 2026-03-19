#include "history/view/secret_chat_section.h"

#include "data/secret/secret_chat_manager.h"
#include "data/secret/secret_chat_types.h"
#include "dialogs/dialogs_key.h"
#include "ui/painter.h"

#include "rpl/filter.h"
#include "rpl/consumer.h"

#include <variant>

namespace HistoryView {

SecretChatMemento::SecretChatMemento(int64_t chatId)
: _chatId(chatId) {
}

object_ptr<Window::SectionWidget> SecretChatMemento::createWidget(
		QWidget *parent,
		not_null<Window::SessionController*> controller,
		Window::Column column,
		const QRect &geometry) {
	if (column == Window::Column::Third) {
		return nullptr;
	}
	auto result = object_ptr<SecretChatWidget>(parent, controller, _chatId);
	result->setGeometry(geometry);
	return result;
}

SecretChatWidget::SecretChatWidget(
		QWidget *parent,
		not_null<Window::SessionController*> controller,
		int64_t chatId)
: SectionWidget(parent, controller)
, _chatId(chatId) {
	Data::SecretChats::Manager(&session()).messageUpdates(
	) | rpl::filter([=](int64_t updatedChatId) {
		return updatedChatId == _chatId;
	}) | rpl::on_next([=](int64_t) {
		update();
	}, lifetime());
}

// We shouldn't return a normal chat because it's not yet implemented to be a full chat, and it can cause issues in some places that expect a full chat. For example, when we open a secret chat from the profile of the other user, the history section is opened with the peer of the other user, and if we return a normal chat here, it will cause issues in the history section because it expects a full chat. So we return an empty descriptor here to avoid issues in the history section, and we can implement it later when we have a full chat implementation for secret chats.
/*Dialogs::RowDescriptor SecretChatWidget::activeChat() const {
	if (const auto entry = Data::SecretChats::Manager(&session()).EntryForChat(_chatId)) {
		return { Dialogs::Key(entry), FullMsgId() };
	}
	return {};
}*/
Dialogs::RowDescriptor SecretChatWidget::activeChat() const {
	if (const auto entry = Data::SecretChats::Manager(&session()).EntryForChat(_chatId)) {
		return { Dialogs::Key(entry), FullMsgId() };
	}
	return {};
}

bool SecretChatWidget::showInternal(
		not_null<Window::SectionMemento*> memento,
		const Window::SectionShow &params) {
	if (const auto secret = dynamic_cast<SecretChatMemento*>(memento.get())) {
		return (secret->chatId() == _chatId);
	}
	return false;
}

bool SecretChatWidget::sameTypeAs(not_null<Window::SectionMemento*> memento) {
	return (dynamic_cast<SecretChatMemento*>(memento.get()) != nullptr);
}

std::shared_ptr<Window::SectionMemento> SecretChatWidget::createMemento() {
	return std::make_shared<SecretChatMemento>(_chatId);
}

bool SecretChatWidget::floatPlayerHandleWheelEvent(QEvent *e) {
	return false;
}

QRect SecretChatWidget::floatPlayerAvailableRect() {
	return rect();
}

void SecretChatWidget::paintEvent(QPaintEvent *e) {
	SectionWidget::paintEvent(e);

	Painter p(this);
	p.setPen(palette().windowText().color());

	int y = 20;
	p.drawText(20, y, title());
	y += 30;

	const auto &messages = Data::SecretChats::Manager(&session()).Messages(_chatId);
	if (messages.isEmpty()) {
		p.drawText(20, y, QString("No in-memory messages."));
		return;
	}

	for (const auto &message : messages) {
		const auto line = formatMessage(message);

		p.drawText(QRect(20, y, width() - 40, 40), Qt::TextWordWrap, line);
		y += 44;
	}
}

QString SecretChatWidget::title() const {
	return QString("Secret Chat %1").arg(_chatId);
}

QString SecretChatWidget::formatMessage(
		const Data::SecretChats::SecretParsedMessage &message) const {
	QString line;
	std::visit([&](const auto &value) {
		using T = std::decay_t<decltype(value)>;
		if constexpr (std::is_same_v<T, Data::SecretChats::SecretParsedTextMessage>) {
			line = value.text;
		} else if constexpr (std::is_same_v<T, Data::SecretChats::SecretParsedServiceMessage>) {
			line = QString("[service 0x%1]").arg(
				value.actionConstructor,
				8,
				16,
				QLatin1Char('0'));
		} else if constexpr (std::is_same_v<T, Data::SecretChats::SecretParsedUnsupportedMessage>) {
			line = QString("[unsupported %1]").arg(value.description);
		}
	}, message);
	return line;
}

} // namespace HistoryView