use warp::Filter;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DavResource {
    pub path: String,
    pub is_collection: bool,
    pub size: Option<u64>,
    pub last_modified: i64,
    pub content_type: Option<String>,
    pub etag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DavPrincipal {
    pub id: String,
    pub display_name: String,
    pub email: String,
}

pub struct WebDavHandler {
    resources: Arc<RwLock<HashMap<String, DavResource>>>,
    principals: Arc<RwLock<HashMap<String, DavPrincipal>>>,
    root_path: PathBuf,
}

impl WebDavHandler {
    pub fn new(root_path: PathBuf) -> Self {
        WebDavHandler {
            resources: Arc::new(RwLock::new(HashMap::new())),
            principals: Arc::new(RwLock::new(HashMap::new())),
            root_path,
        }
    }

    pub async fn get_resource(&self, path: &str) -> Option<DavResource> {
        let resources = self.resources.read().await;
        resources.get(path).cloned()
    }

    pub async fn list_collection(&self, path: &str) -> Vec<DavResource> {
        let resources = self.resources.read().await;
        resources
            .iter()
            .filter(|(resource_path, _)| resource_path.starts_with(path) && *resource_path != path)
            .map(|(_, resource)| resource.clone())
            .collect()
    }

    pub async fn create_resource(&self, path: String, resource: DavResource) -> Result<(), Box<dyn std::error::Error>> {
        let mut resources = self.resources.write().await;
        resources.insert(path, resource);
        Ok(())
    }

    pub async fn delete_resource(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut resources = self.resources.write().await;
        resources.remove(path);
        Ok(())
    }

    pub async fn move_resource(&self, from: &str, to: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut resources = self.resources.write().await;
        if let Some(resource) = resources.remove(from) {
            let mut updated_resource = resource;
            updated_resource.path = to.to_string();
            resources.insert(to.to_string(), updated_resource);
        }
        Ok(())
    }

    pub async fn get_principal(&self, id: &str) -> Option<DavPrincipal> {
        let principals = self.principals.read().await;
        principals.get(id).cloned()
    }

    pub async fn create_principal(&self, principal: DavPrincipal) -> Result<(), Box<dyn std::error::Error>> {
        let mut principals = self.principals.write().await;
        principals.insert(principal.id.clone(), principal);
        Ok(())
    }
}

// CalDAV specific functionality
pub struct CalDavHandler {
    webdav: Arc<WebDavHandler>,
}

impl CalDavHandler {
    pub fn new(webdav: Arc<WebDavHandler>) -> Self {
        CalDavHandler { webdav }
    }

    pub async fn create_calendar(&self, path: &str, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let calendar_resource = DavResource {
            path: format!("{}/{}", path, name),
            is_collection: true,
            size: None,
            last_modified: chrono::Utc::now().timestamp(),
            content_type: Some("text/calendar".to_string()),
            etag: format!("\"{}\"", uuid::Uuid::new_v4()),
        };

        self.webdav.create_resource(calendar_resource.path.clone(), calendar_resource).await
    }

    pub async fn create_event(&self, calendar_path: &str, event_data: &str) -> Result<String, Box<dyn std::error::Error>> {
        let event_id = uuid::Uuid::new_v4().to_string();
        let event_path = format!("{}/{}.ics", calendar_path, event_id);

        let event_resource = DavResource {
            path: event_path.clone(),
            is_collection: false,
            size: Some(event_data.len() as u64),
            last_modified: chrono::Utc::now().timestamp(),
            content_type: Some("text/calendar".to_string()),
            etag: format!("\"{}\"", uuid::Uuid::new_v4()),
        };

        self.webdav.create_resource(event_path.clone(), event_resource).await?;
        Ok(event_path)
    }
}

// CardDAV specific functionality
pub struct CardDavHandler {
    webdav: Arc<WebDavHandler>,
}

impl CardDavHandler {
    pub fn new(webdav: Arc<WebDavHandler>) -> Self {
        CardDavHandler { webdav }
    }

    pub async fn create_addressbook(&self, path: &str, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let addressbook_resource = DavResource {
            path: format!("{}/{}", path, name),
            is_collection: true,
            size: None,
            last_modified: chrono::Utc::now().timestamp(),
            content_type: Some("text/vcard".to_string()),
            etag: format!("\"{}\"", uuid::Uuid::new_v4()),
        };

        self.webdav.create_resource(addressbook_resource.path.clone(), addressbook_resource).await
    }

    pub async fn create_contact(&self, addressbook_path: &str, contact_data: &str) -> Result<String, Box<dyn std::error::Error>> {
        let contact_id = uuid::Uuid::new_v4().to_string();
        let contact_path = format!("{}/{}.vcf", addressbook_path, contact_id);

        let contact_resource = DavResource {
            path: contact_path.clone(),
            is_collection: false,
            size: Some(contact_data.len() as u64),
            last_modified: chrono::Utc::now().timestamp(),
            content_type: Some("text/vcard".to_string()),
            etag: format!("\"{}\"", uuid::Uuid::new_v4()),
        };

        self.webdav.create_resource(contact_path.clone(), contact_resource).await?;
        Ok(contact_path)
    }
}

// WebDAV HTTP method handlers
pub async fn handle_propfind(
    handler: Arc<WebDavHandler>,
    path: &str,
    depth: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let depth = depth.unwrap_or("1");

    let mut response = r#"<?xml version="1.0" encoding="utf-8"?>
<multistatus xmlns="DAV:">"#.to_string();

    if let Some(resource) = handler.get_resource(path).await {
        response.push_str(&format_resource_xml(&resource));
    }

    if depth == "1" {
        let children = handler.list_collection(path).await;
        for child in children {
            response.push_str(&format_resource_xml(&child));
        }
    }

    response.push_str("</multistatus>");
    Ok(response)
}

pub async fn handle_proppatch(
    handler: Arc<WebDavHandler>,
    path: &str,
    properties: HashMap<String, String>,
) -> Result<String, Box<dyn std::error::Error>> {
    // Update resource properties
    // This is a simplified implementation

    Ok(r#"<?xml version="1.0" encoding="utf-8"?>
<multistatus xmlns="DAV:">
  <response>
    <href>/dav/files</href>
    <propstat>
      <prop>
        <displayname>Test File</displayname>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>
</multistatus>"#.to_string())
}

pub async fn handle_mkcol(
    handler: Arc<WebDavHandler>,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let collection = DavResource {
        path: path.to_string(),
        is_collection: true,
        size: None,
        last_modified: chrono::Utc::now().timestamp(),
        content_type: None,
        etag: format!("\"{}\"", uuid::Uuid::new_v4()),
    };

    handler.create_resource(path.to_string(), collection).await
}

pub async fn handle_put(
    handler: Arc<WebDavHandler>,
    path: &str,
    data: &[u8],
    content_type: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resource = DavResource {
        path: path.to_string(),
        is_collection: false,
        size: Some(data.len() as u64),
        last_modified: chrono::Utc::now().timestamp(),
        content_type: content_type.map(|s| s.to_string()),
        etag: format!("\"{}\"", uuid::Uuid::new_v4()),
    };

    handler.create_resource(path.to_string(), resource).await
}

pub async fn handle_delete(
    handler: Arc<WebDavHandler>,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    handler.delete_resource(path).await
}

pub async fn handle_move(
    handler: Arc<WebDavHandler>,
    from: &str,
    to: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    handler.move_resource(from, to).await
}

fn format_resource_xml(resource: &DavResource) -> String {
    format!(
        r#"
  <response>
    <href>{}</href>
    <propstat>
      <prop>
        <getcontenttype>{}</getcontenttype>
        <getcontentlength>{}</getcontentlength>
        <getlastmodified>{}</getlastmodified>
        <getetag>{}</getetag>
        <resourcetype>{}</resourcetype>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>"#,
        resource.path,
        resource.content_type.as_ref().unwrap_or(&"".to_string()),
        resource.size.unwrap_or(0),
        chrono::DateTime::from_timestamp(resource.last_modified, 0)
            .unwrap_or(chrono::Utc::now())
            .format("%a, %d %b %Y %H:%M:%S GMT"),
        resource.etag,
        if resource.is_collection { "<collection/>" } else { "" }
    )
}