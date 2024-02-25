import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";

describe("Demo", function () {
  async function deployFixture() {
    const demo = await ethers.deployContract("DemoUpgradeable");
    return { demo };
  }

  it("Should initialize correctly", async function () {
    const { demo } = await loadFixture(deployFixture);
    expect(await demo.getValue()).to.equal(0);
  });

  it("Should set value correctly", async function () {
    const { demo } = await loadFixture(deployFixture);
    await demo.setValue(10);
    expect(await demo.getValue()).to.equal(10);
  });
});
