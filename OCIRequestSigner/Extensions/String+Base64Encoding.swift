//
//  String+Base64Encoding.swift
//  OCI Request Signer
//
//  Created by Scott Harwell on 9/21/19.
//  Copyright © 2019 Scott Harwell. All rights reserved.
//

import Foundation

extension String {
    /**
     Returns a new string with the base64 encoded version of the current string.
    */
    var base64Encoded: String? {
        return data(using: .utf8)?.base64EncodedString()
    }
    
    /**
     Returns a new string with the base64 decoded version of the current string.
     */
    var base64Decoded: String? {
        guard let data = Data(base64Encoded: self) else { return nil }
        return String(data: data, encoding: .utf8)
    }
    
    /**
     Converts the current string text to base64 encoding.
     */
    mutating func base64Encode() {
        self = base64Encoded ?? ""
    }
    
    /**
     Converts the current string text from base64 encoding.
     */
    mutating func base64Decode() {
        self = base64Decoded ?? ""
    }
}
