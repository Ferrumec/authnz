use crate::authz::admin::Perm;
use crate::authz::{db::get_permission_set, services::Service};
use serde::{Deserialize, Serialize};
use sqlx::{Error, Pool, Postgres, QueryBuilder, postgres::PgQueryResult};
use std::{collections::HashMap, env::VarError, fmt::Display, num::ParseIntError};
use uuid::Uuid;

#[derive(Clone)]
pub struct Permission {
    pub value: u128,
    name: String,
}

#[derive(Deserialize, Serialize)]
pub struct PermissionReq {
    pub permission: String,
    pub target: Uuid,
}

#[derive(Clone)]
pub struct AppState {
    pub service: Service,
}

pub enum ReadError {
    VarError(VarError),
    ParseIntError(ParseIntError),
}

pub fn perm2permission(perm: Perm) -> Permission {
    Permission {
        name: perm.name,
        value: 1 << perm.value,
    }
}

pub fn permission2perm(perm: Permission) -> Perm {
    Perm {
        name: perm.name,
        value: perm.value.trailing_zeros() as i64,
    }
}

#[derive(Debug)]
pub enum LoadError {
    Sqlx(Error),
    Capacity(CapacityError),
    CorruptedData,
}

impl Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Sqlx(error) => write!(f, "{}", *error),
            LoadError::Capacity(CapacityError) => {
                write!(f, "namespace permission capacity is full")
            }
            LoadError::CorruptedData => write!(
                f,
                "The permission set loaded from the database is corrupted"
            ),
        }
    }
}

impl From<Error> for LoadError {
    fn from(value: Error) -> Self {
        LoadError::Sqlx(value)
    }
}

impl From<PermError> for LoadError {
    fn from(value: PermError) -> Self {
        match value {
            PermError::Capacity(value) => LoadError::Capacity(value),
            PermError::Reuse => LoadError::CorruptedData,
        }
    }
}

pub struct PermissionSet {
    map: HashMap<String, i64>,
    next_value: i64,
}

#[derive(Debug)]
pub enum PermError {
    Capacity(CapacityError),
    Reuse,
}

impl Display for PermError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PermError::Capacity(_v) => write!(f, "namespace capacity is full"),
            PermError::Reuse => write!(f, "permission name reused"),
        }
    }
}

#[derive(Debug)]
pub struct CapacityError;

pub trait LogErr {
    fn log_err(self, msg: &str) -> Self;
}

impl<T, E> LogErr for Result<T, E>
where
    E: Display,
{
    fn log_err(self, msg: &str) -> Self {
        match self {
            Ok(_) => (),
            Err(ref e) => print!("{} : {}", msg, e),
        };
        self
    }
}

impl PermissionSet {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            next_value: 1,
        }
    }

    pub async fn load_from_db(db: &Pool<Postgres>) -> Result<Self, LoadError> {
        let perms = get_permission_set(db)
            .await
            .map_err(LoadError::Sqlx)
            .log_err("error in get perm set")?;
        verify_perm_set(perms.clone())?;
        let mut set = PermissionSet::new();

        let mut max = set.next_value;
        for perm in &perms {
            set.map.insert(perm.name.clone(), perm.value);
            if perm.value > max {
                max = perm.value;
            }
        }
        set.next_value = max + 1;

        Ok(set)
    }

    pub async fn add_new(
        &mut self,
        strings: Vec<String>,
        db: &Pool<Postgres>,
    ) -> Result<Vec<Permission>, LoadError> {
        let mut result: Vec<Permission> = Vec::new();
        let mut new: Vec<Perm> = Vec::new();
        for string in strings {
            match self.add(string.clone()) {
                Ok(perm) => new.push(perm),
                Err(e) => match e {
                    PermError::Capacity(capacity_error) => {
                        return Err(LoadError::Capacity(capacity_error));
                    }
                    PermError::Reuse => (),
                },
            };
            let perm = self.get_perm(&string).unwrap();
            result.push(perm);
        }
        self.insert_perms(db, new).await?;
        Ok(result)
    }
    pub fn add(&mut self, name: String) -> Result<Perm, PermError> {
        // Check if the namespace capacity is full
        if self.next_value >= 128 {
            return Err(PermError::Capacity(CapacityError));
        }

        // Check if the permission name is reused
        if self.map.contains_key(&name) {
            return Err(PermError::Reuse);
        }

        // Add the permission to the map and return it
        let value = self.next_value;
        self.next_value += 1;

        self.map.insert(name.clone(), value);

        Ok(Perm { name, value })
    }

    pub fn get_perm(&self, name: &String) -> Option<Permission> {
        self.map.get(name).map(|value| {
            perm2permission(Perm {
                name: name.to_string(),
                value: *value,
            })
        })
    }

    pub async fn insert_perms(
        &self,
        db: &Pool<Postgres>,
        new: Vec<Perm>,
    ) -> Result<PgQueryResult, Error> {
        if new.is_empty() {
            // Nothing to insert — return early
            return Ok(PgQueryResult::default());
        }
        // Start building the query
        let mut qb = QueryBuilder::<Postgres>::new(
            r#"
        INSERT INTO permissions (name, value) 
        "#,
        );

        // Add VALUES
        qb.push_values(new.clone(), |mut b, r| {
            b.push_bind(r.name.clone()).push_bind(r.value);
        });

        // Execute
        qb.build().execute(db).await
    }
}

fn verify_perm_set(perms: Vec<Perm>) -> Result<(), PermError> {
    let mut map: HashMap<String, i64> = HashMap::new();
    for perm in perms {
        if let Some(_r) = map.insert(perm.name, perm.value) {
            return Err(PermError::Reuse);
        };
    }
    if map.len() >= 128 {
        return Err(PermError::Capacity(CapacityError));
    }
    Ok(())
}
