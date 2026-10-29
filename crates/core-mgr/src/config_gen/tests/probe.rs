// SPDX-License-Identifier: GPL-3.0-or-later
//! 测速用的内核配置（`node.test`）。

use super::*;

fn probe_json(nodes: &[NodeOutbound]) -> Result<Value, GenError> {
    let text = generate_probe(nodes, &runtime())?;
    Ok(serde_json::from_str(text.expose()).unwrap())
}

#[test]
fn probe_has_no_inbounds_and_one_outbound_per_node() {
    let v = probe_json(&nodes()).unwrap();
    assert!(
        v.get("inbounds").is_none(),
        "no TUN, no listening proxy port"
    );
    let mut expected = vec![DIRECT_TAG.to_owned()];
    expected.extend(nodes().into_iter().map(|n| n.tag));
    assert_eq!(outbound_tags(&v), expected);
    assert_eq!(v["route"]["final"], DIRECT_TAG);
    assert!(v["route"].get("rules").is_none());
    assert_eq!(
        v["experimental"]["clash_api"]["external_controller"],
        "127.0.0.1:59123"
    );
}

#[test]
fn probe_rejects_duplicate_and_reserved_tags() {
    let mut twice = nodes();
    twice.push(nodes().remove(0));
    assert_eq!(
        probe_json(&twice).unwrap_err(),
        GenError::DuplicateTag(twice[0].tag.clone())
    );
    let mut direct = nodes();
    direct[0].tag = DIRECT_TAG.into();
    assert_eq!(
        probe_json(&direct).unwrap_err(),
        GenError::DuplicateTag(DIRECT_TAG.into())
    );
}

#[test]
fn probe_rejects_a_weak_control_api() {
    let rt = Runtime {
        api_port: 0,
        ..runtime()
    };
    assert_eq!(
        generate_probe(&nodes(), &rt).unwrap_err(),
        GenError::InvalidEndpoint("控制 API")
    );
}

#[test]
fn probe_without_nodes_still_has_direct() {
    let v = probe_json(&[]).unwrap();
    assert_eq!(outbound_tags(&v), [DIRECT_TAG]);
}

#[cfg(windows)]
#[test]
fn sing_box_accepts_the_probe_config() {
    use super::sing_box_check::check;

    let text = generate_probe(&nodes(), &runtime()).unwrap();
    let (ok, log) = check(text.expose(), "probe");
    assert!(ok, "probe config rejected:\n{log}");
    assert!(!log.to_ascii_lowercase().contains("deprecated"), "{log}");
}
