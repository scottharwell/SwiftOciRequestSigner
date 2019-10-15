//
//  ApiVersions.swift
//  OCI Request Signer
//
//  Created by Scott Harwell on 9/22/19.
//  Copyright © 2019 Scott Harwell. All rights reserved.
//

import Foundation

/// Represents the versions of the OCI API that can be used.  As of the writing of this library, v1 is the only version.
public enum ApiVersions: Double, CaseIterable {
    case one = 1
}
