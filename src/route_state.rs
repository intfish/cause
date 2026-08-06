use crate::auth::Keys;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::config::RouteConfig;

#[derive(Clone, Debug)]
pub struct RouteState {
	pub config: RouteConfig,
	pub keys: Arc<Keys>,
	pub semaphore: Arc<Semaphore>,
}
