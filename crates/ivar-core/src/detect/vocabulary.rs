//! The activity vocabulary sensors use in `SecurityEvent.activity_name`.
//! Sensors map their native events to these names so detectors stay
//! independent of any one sensor.

pub const HTTP_REQUEST: &str = "http.request";
pub const AUTH_LOGIN: &str = "auth.login";
pub const AUTH_SIGNUP: &str = "auth.signup";
pub const AUTH_PASSWORD_RESET: &str = "auth.password_reset";
pub const PROCESS_START: &str = "process.start";
pub const FILE_READ: &str = "file.read";
pub const FILE_WRITE: &str = "file.write";
pub const FILE_RENAME: &str = "file.rename";
pub const NET_CONNECT: &str = "net.connect";
pub const DNS_QUERY: &str = "dns.query";
pub const DB_QUERY: &str = "db.query";
pub const DB_SCHEMA_CHANGE: &str = "db.schema_change";
pub const CLOUD_AUDIT: &str = "cloud.audit";
pub const IAM_GRANT: &str = "iam.grant";
pub const OAUTH_GRANT: &str = "oauth.grant";
pub const APP_SECRET_CREATE: &str = "app.secret_create";
pub const PACKAGE_INSTALL: &str = "package.install";
pub const WORKFLOW_CHANGE: &str = "workflow.change";
pub const RUNNER_MEMORY_READ: &str = "runner.memory_read";
pub const REMOTE_SESSION: &str = "remote.session";
pub const EXTENSION_INSTALL: &str = "extension.install";
pub const SNAPSHOT_DELETE: &str = "snapshot.delete";
pub const BACKUP_CHANGE: &str = "backup.change";
pub const VM_MASS_ACTION: &str = "vm.mass_action";
pub const SECRET_READ: &str = "secret.read";
pub const AI_PROMPT: &str = "ai.prompt";
pub const AI_TOOL_CALL: &str = "ai.tool_call";
pub const DATASET_LOAD: &str = "dataset.load";
pub const DEVICE_ADMIN_CREATE: &str = "device.admin_create";
pub const DEVICE_VERSION_CHANGE: &str = "device.version_change";
pub const BUSINESS_ACTION: &str = "business.action";
pub const ENGINE_ALERT: &str = "engine.alert";
pub const SENSOR_HEARTBEAT: &str = "sensor.heartbeat";
pub const SIM_SWAP_SIGNAL: &str = "telco.sim_swap";

/// Shells a web process should never start.
pub const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ash", "ksh", "csh", "cmd.exe", "powershell.exe", "pwsh", "pwsh.exe"];
/// Processes that serve web traffic.
pub const WEB_PROCESSES: &[&str] = &["php-fpm", "php", "httpd", "apache2", "nginx", "node", "java", "python", "python3", "gunicorn", "uwsgi", "w3wp.exe", "ruby", "puma"];
/// Paths that hold secrets.
pub const SECRET_PATHS: &[&str] = &["/etc/shadow", "/.aws/credentials", "/.ssh/id_", "/.env", "/proc/self/environ", "/var/run/secrets/kubernetes.io", "/.docker/config.json", "/.npmrc", "/.git-credentials", "/.kube/config"];
/// Cloud metadata endpoints.
pub const METADATA_ENDPOINTS: &[&str] = &["169.254.169.254", "fd00:ec2::254", "metadata.google.internal", "169.254.170.2"];
