use diesel::table;

table! {
    api_keys (id) {
        id -> Uuid,
        organization_id -> Uuid,
        key_value -> Text,
        label -> Nullable<Varchar>,
        permissions -> Array<Text>,
        quota_limit -> Integer,
        usage_count -> Integer,
        status -> Varchar,
        public_key -> Nullable<Text>,
        private_key -> Nullable<Text>,
        created_at -> Timestamp,
    }
}

table! {
    conversations (id) {
        id -> Uuid,
        organization_id -> Uuid,
        title -> Nullable<Varchar>,
        #[sql_name = "type"]
        type_ -> Varchar,
        created_by -> Nullable<Uuid>,
        is_archived -> Bool,
        last_message_at -> Nullable<Timestamp>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

table! {
    conversation_participants (id) {
        id -> Uuid,
        conversation_id -> Uuid,
        user_id -> Uuid,
        role -> Varchar,
        joined_at -> Timestamp,
        last_read_at -> Nullable<Timestamp>,
        is_muted -> Bool,
    }
}

table! {
    message_attachments (id) {
        id -> Uuid,
        message_id -> Uuid,
        filename -> Varchar,
        original_filename -> Varchar,
        mime_type -> Nullable<Varchar>,
        file_size -> Nullable<Integer>,
        file_url -> Nullable<Text>,
        created_at -> Timestamp,
    }
}

table! {
    message_reactions (id) {
        id -> Uuid,
        message_id -> Uuid,
        user_id -> Uuid,
        reaction -> Varchar,
        created_at -> Timestamp,
    }
}

table! {
    message_reads (id) {
        id -> Uuid,
        message_id -> Uuid,
        user_id -> Uuid,
        read_at -> Timestamp,
    }
}

table! {
    messages (id) {
        id -> Uuid,
        conversation_id -> Uuid,
        sender_id -> Nullable<Uuid>,
        content -> Nullable<Text>,
        message_type -> Varchar,
        reply_to_id -> Nullable<Uuid>,
        is_edited -> Bool,
        edited_at -> Nullable<Timestamp>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

table! {
    organizations (id) {
        id -> Uuid,
        name -> Varchar,
        country_code -> Nullable<Bpchar>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

table! {
    users (id) {
        id -> Uuid,
        organization_id -> Nullable<Uuid>,
        email -> Varchar,
        full_name -> Nullable<Varchar>,
        password_hash -> Text,
        role -> Varchar,
        status -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}