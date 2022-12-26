# 해킹방어대회(CTF) 후기 - CODEGATE 2022 본선 Blockchain Challenge `Look It Up` 문제 풀이

> Aimed to be submitted to KAIST Orakle Blockchain Academy

안녕하세요. 2022년 11월 7일~8일 개최된 CODEGATE 2022 국제해킹방어대회(CTF)에서 KAIST GoN 팀으로 대학생부 [우승](https://cs.kaist.ac.kr/board/view?bbs_id=news&bbs_sn=10476&page=1&skey=subject&svalue=&menu=83)을 하였습니다. 우리 팀은 저 포함 4인 팀으로 구성되었으며, 저는 본선 중 블록체인 및 암호학 관련 문제들을 풀어 우승에 기여하였습니다. 

이 글에서는 CTF에 대한 소개 및, 본선에 출제된 블록체인 문제(문제명: `Look It Up`)에 대한 풀이 및 이를 이해하기 위한 배경지식을 다루고자 합니다. 이 글이 블록체인 보안을 이해하는 데 있어 즐거운 출발점이 되었으면 좋겠습니다.

## CTF란?

CTF는 Capture The Flag의 약자입니다. 정보보안 대회 중 하나로, 암호학(Crypto), 웹 보안(Web Security), 시스템 해킹(Pwnable), 역공학(Reversing) 등 다양한 분야에서 출제된 문제(Challenge)를 푸는 대회입니다. 최근 들어 블록체인 기술이 진화하고, 블록체인 보안의 중요성이 대두됨에 따라 블록체인 보안 관련 문제가 CTF에 등장하고 있습니다. 유명 크립토 투자 회사인 [Paradigm](https://www.paradigm.xyz/)도 매년 블록체인 보안 관련 [Paradigm CTF](https://ctf.paradigm.xyz/)를 개최합니다. 

CTF는 정보보안 전문가부터 뉴비까지 참여하여, 우리들의 실력을 측정하고 향상하는 매우 좋은 기회입니다. 운이 좋으면 저처럼 상금도 얻을 수 있죠. 이 과정에서, 다른 사람들과 협력할 수도 있기에 협동심을 키울 수도 있습니다. 제가 생각하였을 때, CTF의 가장 큰 장점은, 모르는 지식이 등장하였을 때, 두려워하지 않고 빠른 시간 안에 이를 이해하여 응용할 수 있는 능력이 키워진다는 것입니다. 또한, 사소한 디테일까지 빠트리지 않고 문제에 접근하는 능력도 길러집니다.

CTF는 보통 대학교나 회사, 국가 기관이 개최하며, 개인이 대회를 여는 경우도 있습니다. 뉴비를 위한 CTF부터, 정보보안 고인물을 위한 CTF까지, 난이도가 매우 다양합니다. 제가 참여한 [CODEGATE CTF](http://codegate.org/sub/introduce)는 과학기술정보통신부가 주최한, 2008년부터 개최된 유명한 대회입니다. 

그렇다면 CTF 문제를 푼다라는 것은 어떤 의미이며, 채점은 어떻게 이루어지는지 알아봅시다. 문제들은, 출제자가 의도적으로 취약점을 넣어서 작성한 프로그램 혹은 데이터로 이루어집니다. 문제 풀이자는, 취약점을 발견하여 허락되지 않은 데이터를 읽거나, 프로그램을 의도하지 않은 상태로 조종합니다. 그 증거로 flag를 찾습니다. 여기서 통상적으로 flag란, alphanumeric하면서 너무 길지 않은 문자열입니다. 가령, `flag{yay_here_is_your_secret}`가 예시가 되겠습니다. 문제 풀이자는 flag를 출제자의 server에 제출하여, 점수를 얻게 됩니다. 보통은 쉬운 문제 일수록 많이 풀리게 되고, 점수가 떨어지는 Dynamic scoring 방식입니다. 대회 시간동안 얻어낸 점수의 총합이 가장 큰 팀이 우승하게 됩니다. 아래는 실제 대회 Scoreboard입니다.

<p align="center">
    <img src="./codegate22f_scoreboard.jpg" alt="scoreboard" width="200" />
</p>

## CTF 문제 맛보기

아주 간단한 블록체인 문제를 예시로 살펴봅시다. 아래의 이더리움 스마트 컨트랙트 코드 및 그 주소가 문제 풀이자에게 주어집니다.

```solidity
contract Challenge {
    string private flag;

    constructor(string memory _flag) {
        flag = _flag;
    }

    function query() public payable returns (string memory) {
        require(msg.value >= 10000 ether);
        return flag;
    }
}
```

문제의 의도는 명백합니다. 우리는 `flag`의 값을 알아내야 합니다. 언뜻 보기엔 10000 ETH를 지불하여 payable인 `query` 메소드를 호출하여 `flag`를 얻어내야 할 것만 같습니다. 하지만 우리는 저렇게 큰 돈이 없습니다. 어떻게 해야 할까요?

[스마트 컨트랙트 위의 모든 데이터는 읽을 수 있습니다!](https://medium.com/hackernoon/your-private-solidity-variable-is-not-private-save-it-before-it-becomes-public-52a723f29f5e) 변수가 `private`로 선언되었더라도 말이죠. `getStorageAt` Ethereum JSONRPC(`getStorageAt(contract address, 0, latest)`)를 사용하여 slot 0번째 저장공간을 읽으면 `flag`를 얻을 수 있습니다!(`flag` 의 길이가 32 bytes 미만이라고 가정하였습니다. [FYI](https://ethereum.stackexchange.com/questions/107282/storage-and-memory-layout-of-strings)) 문제 풀이자는 얻어낸 `flag`를 출제자의 server에 제출하여, 점수를 얻습니다. 또한 문제 풀이자는 private keyword를 사용하였더라도, 블록체인 위의 모든 데이터는 읽을 수 있다는 중요한 사실을 배웠습니다. 

## CODEGATE 2022 본선 Blockchain Challenge `Look It Up` 같이 풀어보기

더 많은 것을 배우고, flag를 얻기 위해 이제는 CODEGATE 2022 본선 블록체인 문제인 `Look It Up` 문제를 단계별로 같이 풀어봅시다.

Bunch of TODOs