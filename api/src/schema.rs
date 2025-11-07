// @generated automatically by Diesel CLI.

diesel::table! {
    poweradmin_zones (id) {
        id -> Varchar,
        name -> Varchar,
        zone_type -> Varchar,
        nameservers -> Array<Text>,
        serial -> Nullable<Int8>,
        refresh -> Nullable<Int4>,
        retry -> Nullable<Int4>,
        expire -> Nullable<Int4>,
        minimum -> Nullable<Int4>,
        ttl -> Nullable<Int4>,
        owner -> Varchar,
        organization_id -> Varchar,
        created_by -> Varchar,
        updated_by -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        dnssec_enabled -> Bool,
        template_name -> Nullable<Varchar>,
    }
}

diesel::table! {
    poweradmin_records (id) {
        id -> Varchar,
        zone_id -> Varchar,
        name -> Varchar,
        record_type -> Varchar,
        value -> Varchar,
        ttl -> Nullable<Int4>,
        priority -> Nullable<Int4>,
        weight -> Nullable<Int4>,
        port -> Nullable<Int4>,
        organization_id -> Varchar,
        created_by -> Varchar,
        updated_by -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    poweradmin_operation_logs (id) {
        id -> Varchar,
        operation_type -> Varchar,
        zone_id -> Nullable<Varchar>,
        record_id -> Nullable<Varchar>,
        old_value -> Nullable<Text>,
        new_value -> Nullable<Text>,
        organization_id -> Varchar,
        user_id -> Varchar,
        ip_address -> Varchar,
        user_agent -> Nullable<Text>,
        status -> Varchar,
        error_message -> Nullable<Text>,
        created_at -> Timestamp,
    }
}

diesel::table! {
    poweradmin_zone_templates (id) {
        id -> Varchar,
        name -> Varchar,
        description -> Nullable<Text>,
        default_ttl -> Nullable<Int4>,
        default_refresh -> Nullable<Int4>,
        default_retry -> Nullable<Int4>,
        default_expire -> Nullable<Int4>,
        default_minimum -> Nullable<Int4>,
        default_nameservers -> Array<Text>,
        dnssec_enabled -> Bool,
        organization_id -> Varchar,
        created_by -> Varchar,
        updated_by -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    grafana_dashboards (id) {
        id -> Varchar,
        title -> Varchar,
        uid -> Varchar,
        dashboard_json -> Jsonb,
        folder_id -> Nullable<Varchar>,
        organization_id -> Varchar,
        created_by -> Varchar,
        updated_by -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        tags -> Array<Text>,
        is_public -> Bool,
    }
}

diesel::table! {
    grafana_datasources (id) {
        id -> Varchar,
        name -> Varchar,
        type_ -> Varchar,
        url -> Varchar,
        access -> Varchar,
        database -> Nullable<Varchar>,
        user_ -> Nullable<Varchar>,
        password -> Nullable<Varchar>,
        organization_id -> Varchar,
        created_by -> Varchar,
        updated_by -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        is_default -> Bool,
        basic_auth -> Bool,
        basic_auth_user -> Nullable<Varchar>,
        basic_auth_password -> Nullable<Varchar>,
        secure_json_data -> Jsonb,
    }
}

diesel::table! {
    grafana_alert_rules (id) {
        id -> Varchar,
        title -> Varchar,
        description -> Nullable<Text>,
        condition -> Text,
        dashboard_id -> Nullable<Varchar>,
        panel_id -> Nullable<Int4>,
        organization_id -> Varchar,
        created_by -> Varchar,
        updated_by -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        is_enabled -> Bool,
        frequency -> Int4,
        for_duration -> Int4,
        notifications -> Array<Text>,
    }
}

diesel::table! {
    grafana_audit_logs (id) {
        id -> Varchar,
        action -> Varchar,
        resource_type -> Varchar,
        resource_id -> Nullable<Varchar>,
        old_value -> Nullable<Text>,
        new_value -> Nullable<Text>,
        organization_id -> Varchar,
        user_id -> Varchar,
        ip_address -> Varchar,
        user_agent -> Nullable<Text>,
        created_at -> Timestamp,
    }
}

diesel::table! {
    grafana_templates (id) {
        id -> Varchar,
        name -> Varchar,
        description -> Nullable<Text>,
        template_json -> Jsonb,
        category -> Varchar,
        organization_id -> Varchar,
        created_by -> Varchar,
        updated_by -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        is_public -> Bool,
        tags -> Array<Text>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    poweradmin_zones,
    poweradmin_records,
    poweradmin_operation_logs,
    poweradmin_zone_templates,
    grafana_dashboards,
    grafana_datasources,
    grafana_alert_rules,
    grafana_audit_logs,
    grafana_templates,
);