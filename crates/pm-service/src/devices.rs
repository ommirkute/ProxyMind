//! Devices: client addresses seen in history, with names people give them ("Pixel 8").

use std::collections::BTreeMap;

use pm_policy::Actor;
use serde_json::json;

use crate::access::Perm;
use crate::api_types::{DeviceView, DevicesView};
use crate::network::normalize_client_ip;
use crate::{Result, Service, ServiceError};

/// Project setting: a JSON object from client IP address to device name.
pub const DEVICES_SETTING: &str = "devices";

/// Most named devices a project keeps.
const MAX_NAMED: usize = 200;
/// Longest device name.
const MAX_NAME: usize = 60;

impl Service {
    /// Device names by client IP address.
    pub(crate) fn device_names(&self) -> Result<BTreeMap<String, String>> {
        self.store.read(load_names)
    }

    /// Devices seen in history, and any named or selected ones that have not sent anything yet.
    pub fn devices_list(&self) -> Result<DevicesView> {
        let (seen, names) = self.store.read(|db| Ok::<_, ServiceError>((db.client_summary()?, load_names(db)?)))?;
        let only = self.record_devices.read().clone();
        let mut devices: Vec<DeviceView> = seen
            .into_iter()
            .map(|c| DeviceView {
                name: names.get(&c.addr).cloned(),
                record_only: only.contains(&c.addr),
                addr: c.addr,
                exchanges: c.exchanges,
                last_seen_ms: Some(c.last_seen_ms),
            })
            .collect();
        let known: std::collections::HashSet<String> = devices.iter().map(|d| d.addr.clone()).collect();
        let mut extra: std::collections::BTreeSet<&String> = names.keys().chain(only.iter()).collect();
        extra.retain(|a| !known.contains(*a));
        devices.extend(extra.into_iter().map(|a| DeviceView {
            addr: a.clone(),
            name: names.get(a).cloned(),
            exchanges: 0,
            last_seen_ms: None,
            record_only: only.contains(a),
        }));
        Ok(DevicesView { devices })
    }

    /// Names a client address. Humans only (it is the person's own workspace).
    pub fn device_set_name(&self, actor: &Actor, addr: &str, name: &str) -> Result<DeviceView> {
        self.require_actor(actor, Perm::DevicesWrite)?;
        let addr = normalize_client_ip(addr)?;
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME || name.chars().any(char::is_control) {
            return Err(ServiceError::Invalid(format!(
                "a device name is 1 to {MAX_NAME} characters, without control characters"
            )));
        }
        self.store.write(|db| -> Result<()> {
            let mut names = load_names(db)?;
            if !names.contains_key(&addr) && names.len() >= MAX_NAMED {
                return Err(ServiceError::Invalid(format!("at most {MAX_NAMED} named devices")));
            }
            names.insert(addr.clone(), name.to_string());
            save_names(db, &names)
        })?;
        self.audit(&actor.id(), "device_name", json!({"addr": addr, "name": name}), "allow")?;
        self.device_view(&addr)
    }

    /// Removes a device's name.
    pub fn device_remove_name(&self, actor: &Actor, addr: &str) -> Result<()> {
        self.require_actor(actor, Perm::DevicesWrite)?;
        let addr = normalize_client_ip(addr)?;
        let removed = self.store.write(|db| -> Result<bool> {
            let mut names = load_names(db)?;
            let had = names.remove(&addr).is_some();
            if had {
                save_names(db, &names)?;
            }
            Ok(had)
        })?;
        if !removed {
            return Err(ServiceError::NotFound(format!("no name for {addr}")));
        }
        self.audit(&actor.id(), "device_name_removed", json!({"addr": addr}), "allow")?;
        Ok(())
    }

    fn device_view(&self, addr: &str) -> Result<DeviceView> {
        let list = self.devices_list()?;
        list.devices
            .into_iter()
            .find(|d| d.addr == addr)
            .ok_or_else(|| ServiceError::NotFound(format!("device {addr}")))
    }

    /// `client` of a history filter, resolved to IP addresses: an address itself, and every address whose device
    /// name is this text (case-insensitive).
    pub(crate) fn clients_matching(&self, client: &str) -> Result<Vec<String>> {
        let client = client.trim();
        let mut ips: Vec<String> =
            self.device_names()?.into_iter().filter(|(_, n)| n.eq_ignore_ascii_case(client)).map(|(a, _)| a).collect();
        if let Ok(ip) = normalize_client_ip(client)
            && !ips.contains(&ip)
        {
            ips.push(ip);
        }
        Ok(ips)
    }
}

fn load_names(db: &pm_store::Store) -> Result<BTreeMap<String, String>> {
    match db.get_setting(DEVICES_SETTING)? {
        Some(t) => serde_json::from_str(&t)
            .map_err(|e| ServiceError::Invalid(format!("saved device names are unreadable: {e}"))),
        None => Ok(BTreeMap::new()),
    }
}

fn save_names(db: &mut pm_store::Store, names: &BTreeMap<String, String>) -> Result<()> {
    let text = serde_json::to_string(names).map_err(|e| ServiceError::Invalid(e.to_string()))?;
    db.set_setting(DEVICES_SETTING, &text)?;
    Ok(())
}
