/* tslint:disable:no-unused-expression */
/*
 * Copyright 2019. Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *          http://aws.amazon.com/apache2.0/
 *
 *  or in the "license" file accompanying this file.
 *  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 *  OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions
 *  and limitations under the License.
 *
 */

import {handler} from "../src";
import {expect} from "chai";

describe("lambda handler", () => {

  it("GET success - empty params", async () => {

    const result = await handler({
      request: {
        groupConfiguration:
          {
            groupsToOverride: [],
            iamRolesToOverride: [],
            preferredRole: [],
          },
        userAttributes: {},
      },
      response: {},
    });

    expect(result.response.claimsOverrideDetails!.claimsToSuppress).to.be.empty;
    expect(result.response.claimsOverrideDetails!.groupOverrideDetails!.groupsToOverride).to.be.empty;
    expect(result.response.claimsOverrideDetails!.claimsToAddOrOverride).to.be.undefined;

  });

  it("GET success - via attributes", async () => {

    const result = await handler({
      request: {
        groupConfiguration:
          {
            groupsToOverride: [],
            iamRolesToOverride: [],
            preferredRole: [],
          },
        userAttributes: {
          "custom:ADGroups": "[test1, test2]",
        },
      },
      response: {},
    });

    console.log(result.response);

    expect(result.response.claimsOverrideDetails!.claimsToSuppress).to.contain("custom:ADGroups");
    // tslint:disable-next-line:max-line-length
    expect(result.response.claimsOverrideDetails!.groupOverrideDetails!.groupsToOverride).to.have.members(["test1", "test2"]);
    // expect(result.response.claimsOverrideDetails!.claimsToAddOrOverride).to.be.undefined;

  });

  it("GET success - prior groups, empty attribute", async () => {

    const result = await handler({
      request: {
        groupConfiguration:
          {
            groupsToOverride: ["test"],
            iamRolesToOverride: [],
            preferredRole: [],
          },
        userAttributes: {
          "custom:ADGroups": "[]",
        },
      },
      response: {},
    });

    console.log(result.response);

    expect(result.response.claimsOverrideDetails!.claimsToSuppress).to.contain("custom:ADGroups");
    // tslint:disable-next-line:max-line-length
    expect(result.response.claimsOverrideDetails!.groupOverrideDetails!.groupsToOverride).to.have.members(["test"]);
    // expect(result.response.claimsOverrideDetails!.claimsToAddOrOverride).to.be.undefined;

  });
  it("GET success - mix", async () => {

    const result = await handler({
      request: {
        groupConfiguration:
          {
            groupsToOverride: ["test"],
            iamRolesToOverride: [],
            preferredRole: [],
          },
        userAttributes: {
          "custom:ADGroups": "[test2]",
        },
      },
      response: {},
    });

    console.log(result.response);

    expect(result.response.claimsOverrideDetails!.claimsToSuppress).to.contain("custom:ADGroups");
    // tslint:disable-next-line:max-line-length
    expect(result.response.claimsOverrideDetails!.groupOverrideDetails!.groupsToOverride).to.have.members(["test", "test2"]);
    // expect(result.response.claimsOverrideDetails!.claimsToAddOrOverride).to.be.undefined;

  });

  it("GET success - prior groups, no attribute", async () => {

    const result = await handler({
      request: {
        groupConfiguration:
          {
            groupsToOverride: [ "test", "test2" ],
            iamRolesToOverride: [],
            preferredRole: [],
          },
        userAttributes: {
        },
      },
      response: {},
    });

    console.log(result.response);

    expect(result.response.claimsOverrideDetails!.claimsToSuppress).to.be.empty;
    // tslint:disable-next-line:max-line-length
    expect(result.response.claimsOverrideDetails!.groupOverrideDetails!.groupsToOverride).to.have.members(["test", "test2"]);
    // expect(result.response.claimsOverrideDetails!.claimsToAddOrOverride).to.be.undefined;

  });

});