import { Buffer } from "buffer";
import { Client as ContractClient, Spec as ContractSpec, } from "@stellar/stellar-sdk/contract";
export * from "@stellar/stellar-sdk";
export * as contract from "@stellar/stellar-sdk/contract";
export * as rpc from "@stellar/stellar-sdk/rpc";
if (typeof window !== "undefined") {
    //@ts-ignore Buffer exists
    window.Buffer = window.Buffer || Buffer;
}
export const Errors = {
    1: { message: "NotFound" },
    2: { message: "Unauthorized" },
    3: { message: "AlreadyInitialized" }
};
export class Client extends ContractClient {
    options;
    static async deploy(
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options) {
        return ContractClient.deploy(null, options);
    }
    constructor(options) {
        super(new ContractSpec(["AAAAAAAAACBJbml0aWFsaXplIHRoZSBjb21taXRtZW50IHN5c3RlbQAAAAppbml0aWFsaXplAAAAAAABAAAAAAAAAAZfYWRtaW4AAAAAABMAAAABAAAD6QAAA+0AAAAAAAAAAw==",
            "AAAAAAAAABxGZXRjaCBhbiBleGlzdGluZyBjb21taXRtZW50AAAADmdldF9jb21taXRtZW50AAAAAAABAAAAAAAAAANfaWQAAAAABgAAAAEAAAPpAAAH0AAAAA5Db21taXRtZW50U3BlYwAAAAAAAw==",
            "AAAAAAAAABdDcmVhdGUgYSBuZXcgY29tbWl0bWVudAAAAAARY3JlYXRlX2NvbW1pdG1lbnQAAAAAAAABAAAAAAAAAAVfc3BlYwAAAAAAB9AAAAAOQ29tbWl0bWVudFNwZWMAAAAAAAEAAAPpAAAABgAAAAM=",
            "AAAAAAAAABNSZXZva2UgYSBjb21taXRtZW50AAAAABFyZXZva2VfY29tbWl0bWVudAAAAAAAAAEAAAAAAAAAA19pZAAAAAAGAAAAAQAAA+kAAAPtAAAAAAAAAAM=",
            "AAAABAAAAAAAAAAAAAAABUVycm9yAAAAAAAAAwAAAAAAAAAITm90Rm91bmQAAAABAAAAAAAAAAxVbmF1dGhvcml6ZWQAAAACAAAAAAAAABJBbHJlYWR5SW5pdGlhbGl6ZWQAAAAAAAM=",
            "AAAAAQAAAAAAAAAAAAAADkNvbW1pdG1lbnRTcGVjAAAAAAAEAAAAAAAAAAZhbW91bnQAAAAAAAsAAAAAAAAADW1ldGFkYXRhX2hhc2gAAAAAAAPuAAAAIAAAAAAAAAAIcHJvdmlkZXIAAAATAAAAAAAAAAt1bmxvY2tfZGF0ZQAAAAAG"]), options);
        this.options = options;
    }
    fromJSON = {
        initialize: (this.txFromJSON),
        get_commitment: (this.txFromJSON),
        create_commitment: (this.txFromJSON),
        revoke_commitment: (this.txFromJSON)
    };
}
