use super::*;

#[tokio::test]
async fn cancellation_does_not_emit_an_image() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _log, tools) = fake_remote_tools_fixture(remote.path());
    let context = roomy_context();
    context.cancel.cancel();
    let result = serde_json::to_value(
        tools
            .call(
                "remote_view_image".to_owned(),
                json!({"host":"dev", "path":remote.path().join("image.png")}),
                context,
            )
            .await,
    )
    .unwrap();
    assert_eq!(result["isError"], true);
    assert_eq!(result["structuredContent"]["error"]["code"], "CANCELLED");
}

#[tokio::test]
async fn excessive_dimensions_are_rejected_before_full_decode() {
    let remote = tempfile::TempDir::new().unwrap();
    let path = remote.path().join("wide.png");
    image::DynamicImage::new_rgb8(16_385, 1)
        .save(&path)
        .unwrap();
    let (_runtime, _log, tools) = fake_remote_tools_fixture(remote.path());
    let result = call_json(
        &tools,
        "remote_view_image",
        json!({"host":"dev", "path":path}),
    )
    .await;
    assert_eq!(result["isError"], true);
    assert!(
        result["content"]
            .as_array()
            .unwrap()
            .iter()
            .all(|block| block["type"] != "image")
    );
}

#[tokio::test]
async fn jpeg_exif_orientation_applies_to_pixels_and_dimensions() {
    let remote = tempfile::TempDir::new().unwrap();
    let path = remote.path().join("rotated.jpg");
    image::DynamicImage::new_rgb8(12, 8).save(&path).unwrap();
    let jpeg = std::fs::read(&path).unwrap();
    // EXIF little-endian TIFF, one IFD entry: Orientation = 6 (90 clockwise).
    let exif = b"Exif\0\0II\x2a\0\x08\0\0\0\x01\0\x12\x01\x03\0\x01\0\0\0\x06\0\0\0\0\0\0\0";
    let mut oriented = jpeg[..2].to_vec();
    oriented.extend_from_slice(&[0xff, 0xe1]);
    oriented.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
    oriented.extend_from_slice(exif);
    oriented.extend_from_slice(&jpeg[2..]);
    std::fs::write(&path, oriented).unwrap();
    let (_runtime, _log, tools) = fake_remote_tools_fixture(remote.path());
    let result = call_json(
        &tools,
        "remote_view_image",
        json!({"host":"dev", "path":path, "detail":"original"}),
    )
    .await;
    assert_eq!(result["structuredContent"]["width"], 8, "{result}");
    assert_eq!(result["structuredContent"]["height"], 12);
    let decoded = image::load_from_memory(
        &base64::engine::general_purpose::STANDARD
            .decode(result["content"][0]["data"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!((decoded.width(), decoded.height()), (8, 12));
}

#[tokio::test]
async fn native_png_once_over_json_rpc() {
    let remote = tempfile::TempDir::new().unwrap();
    let path = remote.path().join("image $(touch SHOULD_NOT_EXIST).png");
    image::DynamicImage::new_rgba8(16, 12).save(&path).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let (_runtime, _log, tools) = fake_remote_tools_with_options(remote.path(), true, &[]);
    let mut session = ProtocolSession::start(tools).await;
    let result = session
        .call("remote_view_image", json!({"host":"dev", "path":path}))
        .await;
    assert_eq!(result["isError"], Value::Null, "{result}");
    assert_eq!(result["content"].as_array().unwrap().len(), 1);
    let block = &result["content"][0];
    assert_eq!(block["type"], "image");
    assert_eq!(block["mimeType"], "image/png");
    let encoded = block["data"].as_str().unwrap();
    let rendered = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    assert_eq!(
        image::load_from_memory(&rendered).unwrap().to_rgba8(),
        image::load_from_memory(&bytes).unwrap().to_rgba8()
    );
    assert!(!result["structuredContent"].to_string().contains(encoded));
    assert!(result["structuredContent"].get("output").is_none());
    assert_eq!(result["structuredContent"]["width"], 16);
    assert_eq!(result["structuredContent"]["resized"], false);
    assert!(!remote.path().join("SHOULD_NOT_EXIST").exists());
    session.close().await;
}

#[tokio::test]
async fn preview_and_original_dimensions() {
    let remote = tempfile::TempDir::new().unwrap();
    let path = remote.path().join("wide.png");
    image::DynamicImage::new_rgba8(3072, 96)
        .save(&path)
        .unwrap();
    let (_runtime, _log, tools) = fake_remote_tools_fixture(remote.path());
    let preview = call_json(
        &tools,
        "remote_view_image",
        json!({"host":"dev", "path":path}),
    )
    .await;
    assert_eq!(
        preview["structuredContent"]["original_width"], 3072,
        "{preview}"
    );
    assert_eq!(preview["structuredContent"]["width"], 1536);
    assert_eq!(preview["structuredContent"]["height"], 48);
    let data = preview["content"][0]["data"].as_str().unwrap();
    let decoded = image::load_from_memory(
        &base64::engine::general_purpose::STANDARD
            .decode(data)
            .unwrap(),
    )
    .unwrap();
    assert!(decoded.has_alpha());
    let original = call_json(
        &tools,
        "remote_view_image",
        json!({"host":"dev", "path":path, "detail":"original"}),
    )
    .await;
    assert_eq!(original["structuredContent"]["width"], 3072);
    assert_eq!(original["structuredContent"]["resized"], false);
}

#[tokio::test]
async fn detect_jpeg_by_content_not_filename() {
    let remote = tempfile::TempDir::new().unwrap();
    let path = remote.path().join("not-an-extension");
    image::DynamicImage::new_rgb8(12, 8)
        .save_with_format(&path, image::ImageFormat::Jpeg)
        .unwrap();
    let (_runtime, _log, tools) = fake_remote_tools_fixture(remote.path());
    let result = call_json(
        &tools,
        "remote_view_image",
        json!({"host":"dev", "path":path}),
    )
    .await;
    assert_eq!(result["content"][0]["mimeType"], "image/jpeg", "{result}");
}

#[tokio::test]
async fn bad_files_never_fall_back_to_base64_text() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _log, tools) = fake_remote_tools_fixture(remote.path());
    for (name, bytes) in [
        ("text.png", b"not an image".as_slice()),
        ("broken.png", b"\x89PNG\r\n\x1a\n".as_slice()),
    ] {
        let path = remote.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        let result = call_json(
            &tools,
            "remote_view_image",
            json!({"host":"dev", "path":path}),
        )
        .await;
        assert_eq!(result["isError"], true, "{result}");
        assert_eq!(
            result["structuredContent"]["error"]["code"],
            "INVALID_ARGUMENT"
        );
        assert!(
            result["content"]
                .as_array()
                .unwrap()
                .iter()
                .all(|block| block.get("data").is_none())
        );
    }
    for (path, code) in [
        (remote.path().join("missing.png"), "NOT_FOUND"),
        (remote.path().to_path_buf(), "INVALID_ARGUMENT"),
    ] {
        let result = call_json(
            &tools,
            "remote_view_image",
            json!({"host":"dev", "path":path}),
        )
        .await;
        assert_eq!(
            result["structuredContent"]["error"]["code"], code,
            "{result}"
        );
    }
    let path = remote.path().join("oversize.png");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(codex_ssh_bridge::MAX_OUTPUT_BYTES + 1)
        .unwrap();
    let result = call_json(
        &tools,
        "remote_view_image",
        json!({"host":"dev", "path":path}),
    )
    .await;
    assert_eq!(result["structuredContent"]["error"]["code"], "OUTPUT_LIMIT");
}

#[tokio::test]
async fn source_larger_than_a_frame_streams_once_and_preview_fits() {
    let remote = tempfile::TempDir::new().unwrap();
    let path = remote.path().join("large.png");
    let mut state = 0x12345678u32;
    let pixels = image::RgbaImage::from_fn(2048, 2048, |_, _| {
        let mut rgba = [0; 4];
        for byte in &mut rgba {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        image::Rgba(rgba)
    });
    pixels.save(&path).unwrap();
    drop(pixels);
    assert!(std::fs::metadata(&path).unwrap().len() > codex_ssh_bridge::MAX_FRAME_BYTES as u64);
    let (runtime, log, tools) = fake_remote_tools_fixture(remote.path());
    let result = call_json(
        &tools,
        "remote_view_image",
        json!({"host":"dev", "path":path}),
    )
    .await;
    assert_eq!(
        result["isError"],
        Value::Null,
        "{}",
        result["structuredContent"]
    );
    assert_eq!(result["structuredContent"]["original_width"], 2048);
    assert!(result["structuredContent"]["width"].as_u64().unwrap() < 1536);
    assert!(serde_json::to_vec(&result).unwrap().len() <= roomy_context().wire_budget.result_bytes);
    let data = base64::engine::general_purpose::STANDARD
        .decode(result["content"][0]["data"].as_str().unwrap())
        .unwrap();
    let decoded = image::load_from_memory(&data).unwrap();
    assert!(decoded.has_alpha());
    assert!(decoded.to_rgba8().pixels().any(|pixel| pixel[3] < 255));
    // The dispatcher logs C for each request: one binary transfer, no remote
    // chunk loop. Large stdout is not exposed as text or retained output_ref.
    let calls = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        calls
            .lines()
            .filter(|line| line.starts_with("C ") || *line == "C")
            .count(),
        1,
        "{calls}"
    );
    assert!(result["structuredContent"].get("output_ref").is_none());
    assert_image_spool_clean(runtime.path());

    let original = call_json(
        &tools,
        "remote_view_image",
        json!({"host":"dev", "path":path, "detail":"original"}),
    )
    .await;
    assert_eq!(
        original["structuredContent"]["error"]["code"],
        "OUTPUT_LIMIT"
    );
    assert_eq!(original["content"][0]["type"], "text");
    assert_image_spool_clean(runtime.path());
}

fn assert_image_spool_clean(directory: &std::path::Path) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            assert_image_spool_clean(&entry.path());
        } else {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(
                !name.ends_with(".stdout") && !name.ends_with(".stderr"),
                "leaked image spool: {}",
                entry.path().display()
            );
        }
    }
}

#[tokio::test]
async fn validate_inputs_before_ssh() {
    let (_runtime, _bridge, tools) = remote_tools_fixture();
    for args in [
        json!({"host":"dev", "path":"relative.png"}),
        json!({"host":"dev", "path":"/image.png", "detail":"invalid"}),
        json!({"host":"dev", "path":"/image.png", "extra":true}),
        json!({"host":"dev", "path":"/image\u{0000}.png"}),
    ] {
        let result = call_json(&tools, "remote_view_image", args).await;
        assert_eq!(result["isError"], true, "{result}");
    }
}

#[tokio::test]
async fn small_wire_budget_returns_error_not_partial_image() {
    let remote = tempfile::TempDir::new().unwrap();
    let path = remote.path().join("image.png");
    image::DynamicImage::new_rgba8(16, 12).save(&path).unwrap();
    let (_runtime, _log, tools) = fake_remote_tools_fixture(remote.path());
    let result = serde_json::to_value(
        tools
            .call(
                "remote_view_image".to_owned(),
                json!({"host":"dev", "path":path}),
                ToolCallContext {
                    cancel: CancellationToken::new(),
                    wire_budget: WireBudget {
                        result_bytes: 64,
                        compact_fallback_bytes:
                            codex_ssh_bridge::mcp::maximum_compact_fallback_result_bytes(),
                    },
                },
            )
            .await,
    )
    .unwrap();
    assert_eq!(result["isError"], true);
    assert_eq!(result["structuredContent"]["error"]["code"], "OUTPUT_LIMIT");
    assert_eq!(result["content"][0]["type"], "text");
}
