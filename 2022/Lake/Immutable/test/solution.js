const Factory = artifacts.require('Factory');
const Solution = artifacts.require('Solution')
const Contract1 = artifacts.require('Contract1');
const Contract2 = artifacts.require('Contract2');
var readline = require('readline');
var reader = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

contract('Factory', (accounts) => {
    it('attack', async () => {
        // test_step1

        let factoryInstance = await Factory.new();
        const account = accounts[0];

        await factoryInstance.deploy({from: account});
        const solutionBeforeInstance = await Solution.at(
            await factoryInstance.solution({ from: account })
        );

        await solutionBeforeInstance.deploy1({from: account});
        const contractBeforeInstance = await Contract1.at(
            await solutionBeforeInstance.contract1({from: account}
        ));

        console.log('contract_before:', contractBeforeInstance.address);

        const rl = new Promise((resolve, _) => {
            reader.question('Input target: ', (target_hex) => {
                let target = hexToBytes(target_hex);
                resolve(target);
            })
        });
        
        let target = await rl.then((target) => { return target; });

        await solutionBeforeInstance.destruct({from: account});

        // test_step2

        await factoryInstance.deploy({from: account});
        const solutionAfterInstance = await Solution.at(
            await factoryInstance.solution({ from: account })
        );

        await solutionAfterInstance.deploy2(target, {from: account});
        const contractAfterInstance = await Contract2.at(
            await solutionAfterInstance.contract2({from: account}
        )); 

        console.log('contract_after:', contractAfterInstance.address);
    });    
});
