#include "dialogs/secret_chat_entry.h"

#include "data/data_session.h"
#include "dialogs/ui/dialogs_layout.h"
#include "ui/painter.h"
#include "styles/style_dialogs.h"

namespace Dialogs {

SecretChatEntry::SecretChatEntry(
		not_null<Data::Session*> owner,
		int64 chatId)
: Entry(owner, Type::SecretChat)
, _chatId(chatId) {
	refreshName();
	updateChatListSortPosition();
}

void SecretChatEntry::refreshName() {
	_name = QString("Secret Chat %1").arg(_chatId);
	indexNameParts();
	updateChatListEntry();
}

void SecretChatEntry::indexNameParts() {
	_nameWords.clear();
	_nameFirstLetters.clear();

	const auto parts = _name.split(' ', Qt::SkipEmptyParts);
	for (const auto &part : parts) {
		const auto lowered = part.toLower();
		_nameWords.emplace(lowered);
		if (!lowered.isEmpty()) {
			_nameFirstLetters.emplace(lowered.front());
		}
	}
}

TimeId SecretChatEntry::adjustedChatListTimeId() const {
	return 1;
}

int SecretChatEntry::fixedOnTopIndex() const {
	return 0;
}

bool SecretChatEntry::shouldBeInChatList() const {
	return true;
}

UnreadState SecretChatEntry::chatListUnreadState() const {
	return {};
}

BadgesState SecretChatEntry::chatListBadgesState() const {
	return {};
}

HistoryItem *SecretChatEntry::chatListMessage() const {
	return nullptr;
}

bool SecretChatEntry::chatListMessageKnown() const {
	return true;
}

const QString &SecretChatEntry::chatListName() const {
	return _name;
}

const QString &SecretChatEntry::chatListNameSortKey() const {
	return _name;
}

int SecretChatEntry::chatListNameVersion() const {
	return 1;
}

const base::flat_set<QString> &SecretChatEntry::chatListNameWords() const {
	return _nameWords;
}

const base::flat_set<QChar> &SecretChatEntry::chatListFirstLetters() const {
	return _nameFirstLetters;
}

void SecretChatEntry::chatListPreloadData() {
}

void SecretChatEntry::paintUserpic(
		Painter &p,
		Ui::PeerUserpicView &view,
		const Dialogs::Ui::PaintContext &context) const {
	const auto x = context.st->padding.left();
	const auto y = context.st->padding.top();
	const auto size = context.st->photoSize;

	p.setPen(Qt::NoPen);
	p.setBrush(st::dialogsUnreadBg);
	p.drawEllipse(x, y, size, size);

	p.setPen(st::dialogsNameFg);
	p.setFont(st::semiboldFont);
	p.drawText(QRect(x, y, size, size), QString("S"), style::al_center);
}

} // namespace Dialogs