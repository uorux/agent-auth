//! Small builders over twilight-model's Discord types (embeds, buttons,
//! selects, modal inputs) and the outgoing message body.

use serde::Serialize;
use time::OffsetDateTime;
use twilight_model::channel::message::component::{
    ActionRow, Button, ButtonStyle, Label, SelectMenu, SelectMenuOption, SelectMenuType, TextInput,
    TextInputStyle,
};
use twilight_model::channel::message::embed::{EmbedField, EmbedFooter};
use twilight_model::channel::message::{AllowedMentions, Component, Embed, EmojiReactionType};
use twilight_model::id::Id;
use twilight_model::util::Timestamp;

pub const COLOR_PENDING: u32 = 0xF1_C4_0F;
pub const COLOR_APPROVED: u32 = 0x2E_CC_71;
pub const COLOR_DENIED: u32 = 0xE7_4C_3C;
pub const COLOR_ENDED: u32 = 0x95_A5_A6;
pub const COLOR_LIST: u32 = 0x34_98_DB;

/// An empty rich embed.
#[must_use]
pub fn embed() -> Embed {
    Embed {
        author: None,
        color: None,
        description: None,
        fields: Vec::new(),
        footer: None,
        image: None,
        kind: "rich".to_owned(),
        provider: None,
        thumbnail: None,
        timestamp: None,
        title: None,
        url: None,
        video: None,
    }
}

/// What may be sent back of an embed read from a message: the parts a bot
/// sets (Discord fills in the others itself).
#[must_use]
pub fn resendable(e: Embed) -> Embed {
    Embed {
        author: e.author,
        color: e.color,
        description: e.description,
        fields: e.fields,
        footer: e.footer.map(|f| EmbedFooter {
            icon_url: None,
            proxy_icon_url: None,
            text: f.text,
        }),
        timestamp: e.timestamp,
        title: e.title,
        url: e.url,
        ..embed()
    }
}

pub fn add_field(e: &mut Embed, name: impl Into<String>, value: impl Into<String>, inline: bool) {
    e.fields.push(EmbedField {
        inline,
        name: name.into(),
        value: value.into(),
    });
}

pub fn set_footer(e: &mut Embed, text: impl Into<String>) {
    e.footer = Some(EmbedFooter {
        icon_url: None,
        proxy_icon_url: None,
        text: text.into(),
    });
}

#[must_use]
pub fn timestamp(t: OffsetDateTime) -> Option<Timestamp> {
    let micros = t.unix_timestamp_nanos().checked_div(1000)?;
    Timestamp::from_micros(i64::try_from(micros).ok()?).ok()
}

/// `<t:{epoch}:{style}>`.
#[must_use]
pub fn discord_time(t: OffsetDateTime, style: char) -> String {
    format!("<t:{}:{style}>", t.unix_timestamp())
}

/// A button. Discord refuses one without a custom id (link buttons aside,
/// which the bot doesn't send), disabled or not, so it isn't optional.
#[must_use]
pub fn button(label: &str, style: ButtonStyle, custom_id: String, disabled: bool) -> Component {
    Component::Button(Button {
        id: None,
        custom_id: Some(custom_id),
        disabled,
        emoji: None,
        label: Some(label.to_owned()),
        style,
        url: None,
        sku_id: None,
    })
}

#[must_use]
pub fn row(components: Vec<Component>) -> Component {
    Component::ActionRow(ActionRow {
        id: None,
        components,
    })
}

#[must_use]
pub fn unicode_emoji(e: &str) -> EmojiReactionType {
    EmojiReactionType::Unicode { name: e.to_owned() }
}

#[must_use]
pub fn select_option(
    label: String,
    description: Option<String>,
    emoji: &str,
    value: String,
    default: bool,
) -> SelectMenuOption {
    SelectMenuOption {
        default,
        description,
        emoji: Some(unicode_emoji(emoji)),
        label,
        value,
    }
}

#[must_use]
pub fn string_select(
    custom_id: String,
    placeholder: &str,
    options: Vec<SelectMenuOption>,
) -> Component {
    Component::SelectMenu(SelectMenu {
        id: None,
        channel_types: None,
        custom_id,
        default_values: None,
        disabled: false,
        kind: SelectMenuType::Text,
        max_values: None,
        min_values: None,
        options: Some(options),
        placeholder: Some(placeholder.to_owned()),
        required: None,
    })
}

/// One modal text input, the way Discord now wants it: a `Label`
/// (the text above the field, ≤ 45 characters) around the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    pub custom_id: &'static str,
    pub label: String,
    pub paragraph: bool,
    pub required: bool,
    pub min_length: Option<u16>,
    pub max_length: Option<u16>,
    pub placeholder: Option<String>,
    pub value: Option<String>,
}

impl Input {
    #[must_use]
    pub fn new(custom_id: &'static str, label: &str) -> Input {
        Input {
            custom_id,
            label: label.to_owned(),
            paragraph: false,
            required: true,
            min_length: None,
            max_length: None,
            placeholder: None,
            value: None,
        }
    }

    #[must_use]
    pub fn component(&self) -> Component {
        Component::Label(Label {
            id: None,
            label: self.label.clone(),
            description: None,
            component: Box::new(Component::TextInput(text_input(self))),
        })
    }
}

#[expect(deprecated, reason = "the TextInput label is set on the Label instead")]
fn text_input(i: &Input) -> TextInput {
    TextInput {
        id: None,
        custom_id: i.custom_id.to_owned(),
        label: None,
        max_length: i.max_length,
        min_length: i.min_length,
        placeholder: i.placeholder.clone(),
        required: Some(i.required),
        style: if i.paragraph {
            TextInputStyle::Paragraph
        } else {
            TextInputStyle::Short
        },
        value: i.value.clone(),
    }
}

/// A modal: what an interaction answers with to ask for text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modal {
    pub custom_id: String,
    pub title: String,
    pub inputs: Vec<Input>,
}

/// Who a message may ping: nobody, or the owner only. Never `@everyone`,
/// roles, or users named in the text (`parse` is always empty).
#[must_use]
pub fn mentions(owner: Option<u64>) -> AllowedMentions {
    AllowedMentions {
        parse: Vec::new(),
        replied_user: false,
        roles: Vec::new(),
        users: owner.and_then(Id::new_checked).into_iter().collect(),
    }
}

/// A file sent with a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// A message to create, edit, or send as an interaction reply/followup.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Message {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embeds: Option<Vec<Embed>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<Component>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_mentions: Option<AllowedMentions>,
    /// 64: ephemeral.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_reference: Option<MessageReference>,
    /// Attachment metadata; filled from `files` when sending.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<AttachmentMeta>>,
    #[serde(skip)]
    pub files: Vec<File>,
}

pub const EPHEMERAL: u64 = 1 << 6;

#[derive(Debug, Clone, Serialize)]
pub struct MessageReference {
    pub message_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttachmentMeta {
    pub id: usize,
    pub filename: String,
}

impl Message {
    /// Plain text that pings nobody.
    #[must_use]
    pub fn text(content: impl Into<String>) -> Message {
        Message {
            content: Some(content.into()),
            allowed_mentions: Some(mentions(None)),
            ..Message::default()
        }
    }

    #[must_use]
    pub fn ephemeral(content: impl Into<String>) -> Message {
        Message {
            flags: Some(EPHEMERAL),
            ..Message::text(content)
        }
    }
}
