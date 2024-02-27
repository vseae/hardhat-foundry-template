import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";
import { ethers } from "hardhat";
const deploy: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployments, getNamedAccounts } = hre;
  const { deployer } = await getNamedAccounts();
  const { deploy } = deployments;
  const DemoArtifact = await deployments.getArtifact("DemoUpgradeable");
  const res = await deploy("DemoUpgradeable", {
    from: deployer,
    args: [],
    log: true,
    deterministicDeployment: false,
    proxy: {
      owner: deployer,
      proxyContract: "OpenZeppelinTransparentProxy",
    },
  });

  const demo = await ethers.getContractAt(DemoArtifact.abi, res.address);

  if ((await demo.name()) === "DEMO") {
    console.log(
      "DemoUpgradeable contract already initialized:",
      await demo.getAddress(),
    );
  } else {
    const tx = await demo.initialize("DEMO", "DE");
    await tx.wait();
  }
};
deploy.tags = ["Demo"];
export default deploy;
