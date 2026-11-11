use oblivion_cli::{proxy, run};
use oblivion_transport::Transport;
use zeroize::Zeroizing;

fn parse(values: &[&str]) -> Result<run::Options<proxy::Request>, &'static str> {
    run::parse(
        &values
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>(),
    )
}

#[test]
fn every_native_agent_keeps_every_argument_after_its_name_unchanged() {
    let native = [
        "--resume",
        "chat-1",
        "--safe",
        "other",
        "--tor",
        "-x",
        "socks5h://not-parsed",
        "--policy",
        "direct",
        "--",
        "",
        "$(not a shell)",
        "a b",
        "città",
        "a\nb",
    ];
    for agent in ["codex", "claude", "opencode2"] {
        let mut args = vec!["--safe", "GB", agent];
        args.extend(native);
        let result = parse(&args).unwrap();
        assert_eq!(result.safe.as_deref(), Some("GB"));
        assert_eq!(result.agent, agent);
        assert_eq!(result.argv, native);
        assert!(result.transport.is_none());
    }
}

#[test]
fn selectors_preserve_default_and_explicit_policy_choices() {
    let default = parse(&["codex"]).unwrap();
    assert!(default.safe.is_none() && default.name.is_none() && default.transport.is_none());
    assert!(default.proxy_profile.is_none() && default.policy.is_none() && !default.ephemeral);
    for (label, policy) in [
        ("open-internet", "open"),
        ("strict", "strict"),
        ("offline", "offline"),
    ] {
        let result = parse(&["--name", "GB", "--policy", label, "--tor", "claude"]).unwrap();
        assert_eq!(result.name.as_deref(), Some("GB"));
        assert_eq!(result.policy, Some(policy));
        assert!(matches!(
            result.transport,
            Some(proxy::Request::Ready(Transport::Tor {}))
        ));
    }
    let ram = parse(&["--ephemeral", "--ephemeral", "opencode2"]).unwrap();
    assert!(ram.ephemeral);
    let profile = parse(&[
        "--proxy-profile",
        "Office",
        "codex",
        "--proxy-profile",
        "native",
    ])
    .unwrap();
    assert_eq!(profile.proxy_profile.as_deref(), Some("Office"));
    assert_eq!(profile.argv, ["--proxy-profile", "native"]);
    assert!(profile.transport.is_none());
}

#[test]
fn missing_values_unknown_agents_and_conflicting_options_are_rejected() {
    for args in [
        vec![],
        vec!["unknown"],
        vec!["--"],
        vec!["--safe"],
        vec!["--name"],
        vec!["--policy"],
        vec!["--proxy"],
        vec!["-x"],
        vec!["--proxy-profile"],
        vec!["--safe", "GB", "--name", "other", "codex"],
        vec!["--name", "GB", "--name", "other", "codex"],
        vec!["--safe", "GB", "--safe", "other", "codex"],
        vec!["--safe", "GB", "--ephemeral", "codex"],
        vec!["--name", "GB", "--ephemeral", "codex"],
        vec!["--tor", "--tor", "codex"],
        vec!["--tor", "-x", "socks5h://192.0.2.1:1080", "codex"],
        vec!["--proxy-profile", "Office", "--tor", "codex"],
        vec![
            "--proxy-profile",
            "Office",
            "--proxy-profile",
            "Other",
            "codex",
        ],
        vec!["--policy", "offline", "--policy", "strict", "codex"],
        vec!["--policy", "direct", "codex"],
    ] {
        assert!(parse(&args).is_err());
    }
}

#[test]
fn explicit_credentials_decode_once_without_dns_form_decoding_or_shell_expansion() {
    for scheme in ["socks5://", "socks5h://"] {
        let proxy::Request::Ready(Transport::Socks5 {
            endpoint,
            authentication,
        }) = proxy::parse(&format!("{scheme}a%40b+%C3%A8:c%3Ad%252F@192.0.2.1:1080")).unwrap()
        else {
            panic!("expected a complete literal proxy")
        };
        assert_eq!(endpoint.to_string(), "192.0.2.1:1080");
        let authentication = authentication.unwrap();
        assert_eq!(authentication.username.as_str(), "a@b+è");
        assert_eq!(authentication.password.as_str(), "c:d%2F");
    }
    let proxy::Request::Ready(Transport::Socks5 { authentication, .. }) =
        proxy::parse("socks5h://192.0.2.1:1080").unwrap()
    else {
        panic!("expected unauthenticated proxy")
    };
    assert!(authentication.is_none());
}

#[test]
fn omitted_proxy_password_is_an_explicit_effect_free_request_for_the_frontend() {
    let result = parse(&[
        "-x",
        "socks5h://a%40b@192.0.2.1:1080",
        "codex",
        "--resume",
        "native-id",
    ])
    .unwrap();
    assert_eq!(result.argv, ["--resume", "native-id"]);
    let result = result
        .resolve_transport(|request| match request {
            proxy::Request::Ready(transport) => Ok(transport),
            proxy::Request::NeedsPassword(request) => {
                request.complete(Zeroizing::new("synthetic-private-password".into()))
            }
            proxy::Request::NeedsResolution(_) => panic!("expected a literal IPv4 proxy"),
        })
        .unwrap();
    let Some(Transport::Socks5 {
        endpoint,
        authentication,
    }) = result.transport
    else {
        panic!("expected authenticated proxy")
    };
    assert_eq!(endpoint.to_string(), "192.0.2.1:1080");
    let authentication = authentication.unwrap();
    assert_eq!(authentication.username.as_str(), "a@b");
    assert_eq!(
        authentication.password.as_str(),
        "synthetic-private-password"
    );
    let proxy::Request::NeedsPassword(request) =
        proxy::parse("socks5h://user@192.0.2.1:1080").unwrap()
    else {
        panic!("expected password request")
    };
    assert!(request.complete(Zeroizing::new(String::new())).is_err());
    assert!(parse(&["--proxy", "socks5h://user@192.0.2.1:1080", "unknown"]).is_err());
}

#[test]
fn errors_are_static_and_invalid_proxy_urls_never_create_a_resolver_or_prompt() {
    for url in [
        "https://secret:credential@192.0.2.1:1080",
        "socks5h://secret:credential@localhost:1080",
        "socks5h://secret:credential@127.0.0.1:1080",
        "socks5h://user@127.0.0.1:1080",
        "socks5h://0.0.0.0:1080",
        "socks5h://10.88.0.1:1080",
        "socks5h://192.0.2.1:0",
        "socks5h://[2001:db8::1]:1080",
        "socks5h://user:%@192.0.2.1:1080",
        "socks5h://user:%gg@192.0.2.1:1080",
        "socks5h://user:%ff@192.0.2.1:1080",
        "socks5h://user:%00@192.0.2.1:1080",
        "socks5h://user:%0A@192.0.2.1:1080",
    ] {
        let Err(error) = proxy::parse(url) else {
            panic!("expected rejected proxy")
        };
        assert!(
            !error.contains("secret") && !error.contains("credential") && !error.contains("user")
        );
    }
}
