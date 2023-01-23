const Attack = artifacts.require("Attack");

module.exports = function(deployer) {
  deployer.deploy(Attack);
};
