// Copyright 2026 The OPA Authors
// SPDX-License-Identifier: Apache-2.0

// Re-export the modules that make up the SDK's public surface so that a single
// `import SwiftOPASDK` gives consumers `OPA.Runtime`, `OPA.Config`, the bundle
// loader / config provider protocols, and the `OPA.Bundle` types. These live in
// separate internal targets (`Runtime`, `Config`) and in the `swift-opa`
// dependency (`Rego`), none of which a consumer can import directly.
@_exported import Config
import Foundation
@_exported import Logging
@_exported import Rego
@_exported import Runtime
