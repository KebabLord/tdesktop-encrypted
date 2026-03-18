#pragma once

#include "window/section_widget.h"
#include "window/section_memento.h"

namespace HistoryView {

class SecretChatMemento final : public Window::SectionMemento {
public:
	explicit SecretChatMemento(int64 chatId);

	[[nodiscard]] int64 chatId() const {
		return _chatId;
	}

	[[nodiscard]] object_ptr<Window::SectionWidget> createWidget(
		QWidget *parent,
		not_null<Window::SessionController*> controller,
		Window::Column column,
		const QRect &geometry) override;

private:
	int64 _chatId = 0;
};

class SecretChatWidget final : public Window::SectionWidget {
public:
	SecretChatWidget(
		QWidget *parent,
		not_null<Window::SessionController*> controller,
		int64 chatId);

	Dialogs::RowDescriptor activeChat() const override;
	bool showInternal(
		not_null<Window::SectionMemento*> memento,
		const Window::SectionShow &params) override;
	bool sameTypeAs(not_null<Window::SectionMemento*> memento) override;
	std::shared_ptr<Window::SectionMemento> createMemento() override;
    
	bool floatPlayerHandleWheelEvent(QEvent *e) override;
	QRect floatPlayerAvailableRect() override;

protected:
	void paintEvent(QPaintEvent *e) override;

private:
	int64 _chatId = 0;
};

} // namespace HistoryView