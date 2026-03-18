#pragma once

#include "dialogs/dialogs_entry.h"

namespace Data::SecretChats {
struct SecretChatDescriptor;
} // namespace Data::SecretChats

namespace Dialogs {

class SecretChatEntry final : public Entry {
public:
	SecretChatEntry(
		not_null<Data::Session*> owner,
		int64 chatId);

	[[nodiscard]] int64 chatId() const {
		return _chatId;
	}

	void refreshName();

	TimeId adjustedChatListTimeId() const override;

	int fixedOnTopIndex() const override;
	bool shouldBeInChatList() const override;
	UnreadState chatListUnreadState() const override;
	BadgesState chatListBadgesState() const override;
	HistoryItem *chatListMessage() const override;
	bool chatListMessageKnown() const override;
	const QString &chatListName() const override;
	const QString &chatListNameSortKey() const override;
	int chatListNameVersion() const override;
	const base::flat_set<QString> &chatListNameWords() const override;
	const base::flat_set<QChar> &chatListFirstLetters() const override;

	void chatListPreloadData() override;
	void paintUserpic(
		Painter &p,
		Ui::PeerUserpicView &view,
		const Dialogs::Ui::PaintContext &context) const override;

private:
	void indexNameParts();

	const int64 _chatId = 0;
	QString _name;
	base::flat_set<QString> _nameWords;
	base::flat_set<QChar> _nameFirstLetters;
};

} // namespace Dialogs