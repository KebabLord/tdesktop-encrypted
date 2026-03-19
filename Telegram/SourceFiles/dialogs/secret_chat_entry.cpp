#include "dialogs/secret_chat_entry.h"

#include "dialogs/ui/dialogs_layout.h"
#include "styles/style_dialogs.h"
#include "ui/painter.h"
#include "ui/text/text_utilities.h"

namespace Dialogs {

SecretChatEntry::SecretChatEntry(not_null<Data::Session*> owner, int64_t chatId)
: Entry(owner, Type::SecretChat)
, _chatId(chatId)
, _name(QString("Secret Chat %1").arg(chatId))
, _userpic(
	Ui::EmptyUserpic::UserpicColor(Ui::EmptyUserpic::ColorIndex(chatId)),
	_name) {
	indexNameParts();
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
	static const auto empty = QString();
	return empty;
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
	Q_UNUSED(view);
	_userpic.paintCircle(
		p,
		context.st->padding.left(),
		context.st->padding.top(),
		context.st->photoSize,
		context.st->photoSize);
}

void SecretChatEntry::indexNameParts() {
	_nameWords.clear();
	_nameFirstLetters.clear();
	const auto prepared = TextUtilities::PrepareSearchWords(_name);
	for (const auto &part : prepared) {
		if (part.isEmpty()) {
			continue;
		}
		_nameWords.insert(part);
		_nameFirstLetters.insert(part[0]);
	}
}

} // namespace Dialogs