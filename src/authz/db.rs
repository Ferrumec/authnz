use sqlx::{Error, Pool, Postgres, query_as};

use crate::authz::admin::Perm;

pub async fn get_permission_set(db: &Pool<Postgres>) -> Result<Vec<Perm>, Error> {
    query_as::<_, Perm>(r#"select name, value from permissions"#)
        .fetch_all(db)
        .await
}
