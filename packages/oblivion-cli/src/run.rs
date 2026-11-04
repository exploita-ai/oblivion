use crate::proxy;

// A launch may hold a secret-bearing transport or an unresolved password.
// Deliberately no Debug implementation.
pub struct Options<T> {
    pub safe: Option<String>,
    pub name: Option<String>,
    pub ephemeral: bool,
    pub transport: Option<T>,
    pub proxy_profile: Option<String>,
    pub policy: Option<&'static str>,
    pub agent: String,
    pub argv: Vec<String>,
}
pub fn parse(args: &[String]) -> Result<Options<proxy::Request>, &'static str> {
    let mut result = Options {
        safe: None,
        name: None,
        ephemeral: false,
        transport: None,
        proxy_profile: None,
        policy: None,
        agent: String::new(),
        argv: vec![],
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--safe" => {
                if result.safe.is_some() {
                    return Err("Duplicate --safe");
                }
                result.safe = Some(args.next().ok_or("Missing Safe name")?.clone());
            }
            "--name" => {
                if result.name.is_some() {
                    return Err("Duplicate --name");
                }
                result.name = Some(args.next().ok_or("Missing Safe name")?.clone());
            }
            "--ephemeral" => result.ephemeral = true,
            "--tor" => {
                if result.transport.is_some() || result.proxy_profile.is_some() {
                    return Err("Choose one transport");
                }
                result.transport =
                    Some(proxy::Request::Ready(oblivion_transport::Transport::Tor {}));
            }
            "--proxy" | "-x" => {
                if result.transport.is_some() || result.proxy_profile.is_some() {
                    return Err("Choose one transport");
                }
                result.transport = Some(proxy::parse(args.next().ok_or("Missing proxy URL")?)?);
            }
            "--proxy-profile" => {
                if result.transport.is_some() || result.proxy_profile.is_some() {
                    return Err("Choose one transport");
                }
                let name = args.next().ok_or("Missing proxy profile name")?;
                result.proxy_profile = Some(name.clone());
            }
            "--policy" => {
                if result.policy.is_some() {
                    return Err("Duplicate --policy");
                }
                result.policy = Some(match args.next().map(String::as_str) {
                    Some("open-internet") => "open",
                    Some("strict") => "strict",
                    Some("offline") => "offline",
                    _ => return Err("Policy must be open-internet, strict or offline"),
                });
            }
            "codex" | "claude" | "opencode2" => {
                result.agent = arg.clone();
                result.argv = args.cloned().collect();
                break;
            }
            _ => {
                return Err("Expected an Oblivion option or an agent. Run oblivion --help.");
            }
        }
    }
    if result.agent.is_empty() {
        return Err("Choose codex, claude or opencode2");
    }
    if (result.ephemeral && (result.safe.is_some() || result.name.is_some()))
        || (result.safe.is_some() && result.name.is_some())
    {
        return Err("A named Safe and --ephemeral cannot be combined");
    }
    Ok(result)
}

impl<T> Options<T> {
    /// Keep one option model while the platform frontend resolves the sole
    /// effectful input: an explicitly requested private proxy password.
    pub fn resolve_transport<U, E>(
        self,
        resolve: impl FnOnce(T) -> Result<U, E>,
    ) -> Result<Options<U>, E> {
        Ok(Options {
            safe: self.safe,
            name: self.name,
            ephemeral: self.ephemeral,
            transport: self.transport.map(resolve).transpose()?,
            proxy_profile: self.proxy_profile,
            policy: self.policy,
            agent: self.agent,
            argv: self.argv,
        })
    }
}
