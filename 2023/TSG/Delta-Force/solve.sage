from elliptic_curve import EC

# speed things up
proof.arithmetic(False)

# Set this to False for faster flag
DEBUG = True

N = 4861176438018509277765150221122126870541685654379801604114760532814287581153000210004207389443213309449018955338869863741674740447811975915078711903955681567092381171537713559560343153877511977292098222368485399204912122010227229078270969924905169787592189375418475308051129528888568681568734206072034666373423912365236817972608366602899547226744432299234711173306225399948633496091891925021506066051269505274591577497904167584767303718241171649947539664809546498443661211509926990737931523544728384428153032760216353730801234655930548104422024130570816728659653538260845032772371478140823258876790879087834215578099103687121280145961921389449249461303695127426477060016215875089488915916633794518511956116049451487462341914580430836466289069310852902452441670591766542607475566151856004189541762250121764347455770924195541519142036527843854325635334990763891612540761801228294679227675034333748671488131374369328481523920448620362794582130982555488343842058198241325525060402667145213028907534526536473479495813172523174608010901013909785818541505226347899760377967331689016937903306728695776347712900417640623152047417427405267791933202247836823133253708561331399337585694285673510222776175851823031760492810621651225757782530492371
a1 = 3444824117328398332287263145797436732251806993106742790395834211847964497185277822582276657225459760388222788879721727159251866924984494193150653447997603422024763484501407319338008268962141938450376210742802690040775147155751979207058246773645433214949878635670705292205381078390234806850698450436295039666701444937613310617521432088399287665787963949201472844240626719755639541622668049779611715534511220207225102143578882951630506067975785576764801948143058724733822144338788356792891770883002340632245863711872613052190283826616336575324956755899252734899170625497650729243855116042931056447582929301386147920258970755559531421290327063656641559627787073648816453940473655239389908124156165660612689742708373129625588902351602100066924000586976472002309478648159182392535906994995800868902052484891895077235974622067641022944028349866339918120322601296386357756768384853576175451997137719762217320524852380281306558568086807531481968542709466317624453868591793889254468119495169851711195495759784642140806249730424816684480869755835873209370137831042713895026824607183567837804652629953877811080875706500232620906814427668853420025632618707903884500390164422694087209611134445691988003327081785238633702578226975041727958225979248
a2 = 4220657222012863331324022021142115292430597859080918473466273569402786623644966310284686263413321809614975935231589489145653176283755430651257679731781262317639561791314044939921047444940366477586782714676520254598940573251619654210976091118990997406140690658178297711641467793763708001463760191631954449349373914543810395796693214118750609853712197438805175066472570862155591695398007261950273250419125590885574184123001650088433861794755115025331664101776274304102152026455526993460636375440860820326183280743695950579713987688972720640809806839932354448804340284231962944525194259756907531717198723001750563548268505211429663171672155787847084254266041562202569381862742321261337515852288555029875114541634885657856133098628215411753502113867694678392848794557484127610549206348398062803815886751442822499835138675419957858172635972565996494066738623225918806510140877651509362663492336907193615683425402286293202044753906775875048228709714069705104761393891056850481333000346334315445516137338415611089281223529138332726805624561300099605623576433557163093276115663323973176583225088838201896098818427080076586531335010187255421257962154369044435187402303275044435710879669190744621547057417343865042642742729067785757980481708859
a3 = 558053328032569214424924749545080533443204882028700727482902138363914391087914135627507971718720092171365715176468371521485896504111397460977870822260356387271441953304205921733941102285137843514136574063019959717801987678942331305387691085139598494776572670276131522348754285564338055692053988854672468173283148136803799971745169459014171760554786948833430079164649604597281764343627794445260768624935380114208794996054926094746197686261155891021796742555943693683944342826702912295474954080037614961638746950712216471978826697133699862893226784981265765142815822633931592954799220290654691131583229398813285377913420963860081950349348483037678920450399593707900050487766675868613974940533801078648072478704480320992819463523521796820516675896346804256470328012501588846038478735042417434318823499002305595773925357668467999973946928610673937683220558175159559156997545114017452579732447461296275895921770517350210742318724221387478901570280816476239783222112611595977063375839821604111374772017365123591082565390414268391105301111128872682556523124017007950528192427992576438666158999223964016832132347716369554217989660103488591183333215808683339519953259563788055147227130961325434300468212866224123613198733255438000371632201922
a4 = 2409686375529009789062931255151047632553317432871776325977708342575413199868316454516429658254297349908818913648555980905703570378332587211687821833449657319227648023632420349187191203817874908900476265222298630491560124293474130368070578796806092666424986915614853373703916476738812448576677939067552273549664051607033578697950875075526433604321513839183621143953874375023537101509580661583818118731853042627460126855311689628082748074373313182940270826734960431153626135619589835441991890840853823329308534081784864288751938169059434234048947117786007806754996810687735558766333300269431436238258613338745620540366591367671960393239014177679790515185719633955796780366907613116424879434375841785615553717631204945754610331568039531504256955328591989055229298718736414870488253515207480047458000235126179100545819505116852001595203600550936946736697235151062411659082614156384876100227239703938652351269150744501265963390460907632240209469881951684654686080310235283814858158697321466052098007166972602271670115754787224397477919994078767466888020504989901616066772072069140729395181856385314368564511799911756649356907893283650510564887020660017016305620069469798431462964593287090869656274770620420259560247021263773251031107077438
a6 = 3470078186850975739936630083585896206711668380019576458144812382551000399461688662828677551712010444136267839539406491436511536191302115255607338126938721757383820709517878001719275207381244220611138211706395289668473890524220737794043932299829801331641728237036572688318923881312268142947916987785394869895788825813684029625439890374199544512146238573470714240061775578066493778177577497298263101431584499987449107860867974717092406776136120389083101744667140157701396393579936132771094350025878985948459504771054936108295811485497516064375315362547356890406207151247645039645122690527467942787823829138406220130486124334447966832679079367832094353016955534024520702689217787284596726932360141615033646357533622370473604448340917687731406312733759882955505680683319971990286000213361326741481930432680541754817125379558827748942025713721383525941123614481097102581692748593322507617409022332312218948944026657739136377028053975532295249075420561511608283484307148039184136388494407661178023614238682702894250591567479031985618265675418397712856074006023785411792521236472702522327496551883792053117847879265359876050067289453559871911346351148700042996957200697205104421637140069904198053600305602065464319177142877679781718358115411

# base point
Px = 3187380289473628229166076722741605522066106734974330968029363462853994178034889323396549034418774714004310597327299938638132972121767717298791108552121182926252120215568543440680511528729320460150972551785766528743150693345444523026329817473750107100977751329156774721144063214517285726358018274335181425122425497682910915355289941993635789204613409760838922069179423532756084124424087369187079085568561566146028731452307769275341282229672567986555625437613270131401345164990913073456655478295677780849952336452819811133154540184923229453881172046434709663594257091451745029926858800906234840424320289294896839680690069966831649763526212416442961133572796128363987883784263178284726172207323075552538055360106875136163073733438818095552239514221846774992407935815625138205772383894721080363344299257591334491217283076801413291378680281026191916099741354829618889407157244425285493750026510597867261891663671051439047441921123676903663738851276574650416199443198000844605048534594681961771316401603946312451699473847875708346024353289399679978116606272338553246201412764667063871923809515939019235129599135013826180754092409070369916743385338966842753295793028555461533907357857077718994569945179301205081583517722938903924076665161044
Py = 3098509628622199032118889410483498131367153585346875063187101858846530923677876883688759300004198379875832388354339483427258628984564188587177660880817830979516874750329732607401997056978414818886317043638783781007690534739021969383875639013225069704552442992187754882339991182056369690510439789934317089638780423707333159124535609705606295588910501964436737250259915950704729890743964057623145716533126214373974194784113312896436317252284869588214466286181124050804480953801866558673847704787898982600498747562456653841097050232470321543436789172232099599127971642034835964697711543521559007789014820299180115236028167277348348032904641115578872979829671579406457760784565977595271755930086750953607663935048590611365120577239940466584901735242180094939957609545245177604315541505004948250587350636338636915644227983529643209843144781082102080871034333050105691539153291831079893973988409961640177613779257702061258595947270721984862788409947895289380176754001635912693165856017623626949014494500443988487409429044235792054307487109200214875223031796045288551137200587375732192809300189009239330821740285801646366723787253158915642748289216793582895026761306175028926426159594779782097763953591584903850004456396580915118506266981337
P = (Px, Py)
# target point
Qx = 2940137648302822135887768405733428618361214020026143318586301618329372655276898009551187352450543631241584953409424998458467844898870748818109962017628692856154502911778246629019987248210711081379384038506544899037017094206431000794646201463294660352565581410940316447059413267990280103085282255573960006012422254599380011885107374758617951885988212493389139714778955997592191645456603116305632632160041751363247794842614094023112577912814096859442106924317927245381355215404305882813647647808165973585096785363719791485657642484540219214405059891658285454539795978892636754583882973657007442901458945664345488978832970375753192565978853522306244584220151446267601777829062885902539106413866798108556472482002577646588557387807715633128913787076005721277459341934855424070398364463323364862109833382659277887541400854089319386644417923424987803584644908821750251870682987388817038606082810492054657719015315239443896190699718636785628585029435696899067125128349522932992790811417433696577333575752911124735242072095229457254742656832308956471177564651299639347093754244273997643353109038338400428109043737885400764768339281104454669195785957709561673360000645367092746262324437783858934652428309563075654233156559693135917215127084839
Qy = 4309188751202413994756093118871339651868155545296257835957631283548458290549834043239999619160131639470537688107285148019375428000337112432317175093336043210190860875690929878131126549041446002208047334350876371320870374521378167548031473971584407464547121329256935748386784077512111069027529070091090512274046019879131201709340032343094129650445987190535015392973173123256087780783994874319281164700525019310387007282075836894663864145318825896934077504337916357614201204461113478545772364849985793786972947231991982415597625212515186739391531585821996127328710500026236144903951637427245223426748300366460373759173484339176020599231393473092295681626107718784321631623410699469438511433557396045657573993803277529816220655895923559584651137391079923579080103751692260916441921214236122141145982485958870445890303087859026075184149723430563928025165528170894575097071775485154541104075542976068077112038847635378050578747036715486956987048325200527662369726957499097289967832182678228473153601275262332757733205093157880270604049046032523006585325029448952623263419851474313757519250802143143825231591931300564658633698464656605919184597056629222214865044578470955523959024153014386918508244536074045249645182811691608730763212420747
Q = (Qx, Qy)


def is_singular():
    b2 = a1**2 + 4 * a2
    b4 = 2 * a4 + a1 * a3
    b6 = a3**2 + 4 * a6
    b8 = a1**2 * a6 + 4 * a2 * a6 - a1 * a3 * a4 + a2 * a3**2 - a4**2
    Di = -(b2**2) * b8 - 8 * b4**3 - 27 * b6**2 + 9 * b2 * b4 * b6
    return Di % N == 0


def factor():
    if not DEBUG:
        p = 19966952433773622647280963975099603139887593811319990392386894015754446652166446583126433891381570960655713132784650529099582626057886843845523086233188406269001276634158864443217174272472344936896651588970524709312501309698998984063721586210726769606009586215682950765028731638344224398860877069687796137644867440403571014084723477843620793678398876055430128756284754677588405484857364333795470643784083101380058253039735957367939149090758564175640488705079822217679316031716853338402912047783502678971112202058508589384041927358507109319566814540113223437922507783585905695518188920379272309405106729442789658373543
        q = 243461111761649993207760947168400804284506306341364302214804755342576984247538465504320804181821117732296445218442722698044016495591355224588160790051125271634950950583507948393226492011352077815035445968846776970268783772849695094433790503876703921214802543382520171552286215155198920398561695803081334247520368425036727612588452045666710947993842012648371635039538156053017069542703517491519451818168781094985349793723987927135325283707772252693501877136194933452282923455736306827546620604423399356092100856126588466821433682033880010011027969816147027236415931807322312109176103897969140571047988318244965072490997
        return p, q

    FF = IntegerModRing(N)
    ec = EC(FF, (a1, a2, a3, a4, a6))

    # order of Elliptic curve over GF(p) == p
    # order of Elliptic curve over GF(q) == q + 1
    # scalar multiplication not well defined when multiplying N because order of EC over GF(p * q) = p * (q + 1)
    try:
        ec.scalar(N, P)
    except Exception as e:
        t, _ = list(
            map(
                int,
                str(e).lstrip("inverse of Mod(").rstrip(") does not exist").split(", "),
            )
        )
    p = gcd(t, N)
    assert p != 1 and N % p == 0
    q = N // p
    assert q != 1 and N % q == 0
    return Integer(p), Integer(q)


def solve_quadratic(A, B, C):
    disciminant = B**2 - 4 * A * C
    dsq = disciminant.sqrt()
    if disciminant != 0:
        return [(-B + dsq) / (2 * A), (-B - dsq) / (2 * A)]
    return [-B / (2 * A)]


def calc_singular_point(f):
    FF = f.base_ring()
    p = FF.order()

    dfdx = lambda x, y: FF(a1 * y - 3 * x**2 - 2 * a2 * x - a4)
    dfdy = lambda x, y: FF(2 * y + a1 * x + a3)

    A = FF(6)
    B = FF(4 * a2 + a1**2)
    C = FF(2 * a4 + a1 * a3)
    roots = solve_quadratic(A, B, C)

    for xp in roots:
        yp = FF((-a1 * xp - a3) * pow(2, -1, p))
        assert dfdx(xp, yp) == 0 and dfdy(xp, yp) == 0
        if f.subs(x=xp, y=yp) == 0:
            return xp, yp


def solve_dlp_over_p(p):
    if not DEBUG:
        return 7025039839405611704428712111958349759207458322311670522833450294594383611305677315165985633952030664650635786258165673555465765114643315329353732069777461611751401761914674544356002960784308336509117984388967658384064369100257087912674883067185727519262450590830292550941825022956963193945281389835126338245274010394538063535825061487884323562882347566231815838974746812315006801569379361882901876123000638009135938363380696236844415141937838559729033137284794041322092847877250621506154367893945827762951215514669043938383586688710447277597985025968563205006521697153748676370588892777468314258711170654206087750994
    twoinv = pow(2, -1, p)

    # f is singular curve and forms a cusp
    # order of Elliptic curve over GF(p) == p
    FF = GF(p)
    x, y = FF["x, y"].gens()
    f = x**3 + a2 * x**2 + a4 * x + a6 - y**2 - a1 * x * y - a3 * y
    xp, yp = calc_singular_point(f)

    # change of variables to make (0, 0) as singular point
    f = f.subs(x=x + xp, y=y + yp)
    assert f.subs(x=0, y=0) == 0
    xy_coeff = f.coefficient(x * y)
    f = f.subs(y=y + xy_coeff * twoinv * x)
    assert f == x**3 - y**2, "Given curve is not a cusp"

    # shift points
    Pxp = Px - xp
    Pyp = Py - yp - xy_coeff * twoinv * Pxp
    assert f.subs(x=Pxp, y=Pyp) == 0

    Qxp = Qx - xp
    Qyp = Qy - yp - xy_coeff * twoinv * Qxp
    assert f.subs(x=Qxp, y=Qyp) == 0

    # map to additive group over FF
    Q_ = FF(FF(Qxp) // FF(Qyp))
    P_ = FF(FF(Pxp) // FF(Pyp))

    # solve dlp over additive group
    dp = Q_ // P_

    return Integer(dp)


def solve_dlp_over_q(q):
    if not DEBUG:
        return 154075924574486175347562707909961851402473727702317014643095837103684216209007400449603645038526706544810274253183915272469230486051463763376281249086241018042323557902517109795258549187502855001546939039636627742750565210192130958634960554514582139821851491012805037749372205891490027899780633462385372566211372295338704317555889404525927560364933196695956191547549400570151698776808151665849614088600216427777499739843872660202818084555597128524362080176403087726056343256360787083367650029121152781001815493814784689811694461739837548360105812995919537253775141056337613175724504154405630673812583838536950403083982
    twoinv = pow(2, -1, q)

    FF = GF(q)
    x, y = FF["x, y"].gens()
    f = x**3 + a2 * x**2 + a4 * x + a6 - y**2 - a1 * x * y - a3 * y
    xq, yq = calc_singular_point(f)

    # change of variables to make (0, 0) as singular point
    f = f.subs(x=x + xq, y=y + yq)
    assert f.subs(x=0, y=0) == 0
    xy_coeff = f.coefficient(x * y)
    f = f.subs(y=y + xy_coeff * twoinv * x)

    alpha = 69648069266067636314044490180494272483005368439333015295280079928569332400783941695298148978744893078838315137148433352492347333258004521526063297373684380901537871189646111640956478697552816266022366707651804713450461979482707575033787454334648685550273413257098085445662102823450628577137141761841134857149636989589192193449367679604961034614575291157747711948243409876251150906694559542159907493796340169810720121412117409187192674352899334781549189610082931710233000679155624586252814662213143956642004637553894854962148800124179397710455599240069412011390275901384181819546113301720400545388219052522809395373467
    assert f == x**3 + alpha * x**2 - y**2
    # alpha is not a quadratic residue
    assert kronecker(alpha, q) == -1

    # f is singular curve and forms a node
    # order of Elliptic curve over GF(q) = q + 1
    oq = q + 1
    ec = EC(FF, (a1, a2, a3, a4, a6))
    assert ec.iszeropoint(P) and ec.iszeropoint(Q)
    assert ec.scalar(oq, P) == ec.O and ec.scalar(oq, Q) == ec.O

    # order is smooth!
    from operator import mul
    from functools import reduce

    factors = [2, 2148001447, 2176673621, 2204759833, 2227430017, 2229149491, 2276963327, 2357792531, 2438970631, 2439515711, 2463893021, 2508925567, 2544545561, 2551006313, 2570552119, 2573166007, 2584367263, 2590741051, 2599249069, 2604018539, 2659957969, 2701630493, 2726761391, 2774702377, 2787241907, 2856415589, 2864849627, 2924420089, 2931772031, 2961156127, 3003869681, 3011064019, 3251354779, 3297888277, 3311196061, 3346168723, 3389296819, 3397223771, 3413403971, 3420659117, 3510599767, 3528378703, 3537123631, 3539636329, 3561770857, 3578073617, 3588230683, 3633688213, 3636216587, 3642189263, 3654916073, 3696612989, 3716509367, 3856096117, 3861851249, 3888318667, 3910062161, 3970999633, 3982009877, 4068784919, 4100417567, 4148054873, 4154779879, 4248173437, 4248469033, 4274566939]
    assert reduce(mul, factors) == oq
    # order is B-smooth where B = 2 ** 33
    B = 2**33
    assert all(fac << B for fac in factors)

    # ECPoint class for discrete_log
    class ECPoint:
        def __init__(self, point):
            self.point = point

        def is_zero(self):
            return self.point == EC.O

        def __eq__(self, other):
            return self.point == other.point

        def __hash__(self):
            return hash(self.point)

    # factory method for discrete_log
    add = lambda x, y: ECPoint(ec.add(x.point, y.point))
    inv = lambda x: ECPoint(ec.negate(x.point))

    # wrapping points with ECPoint class
    identity = ECPoint(ec.O)
    P_, Q_ = ECPoint(P), ECPoint(Q)

    # discrete_log time
    dq = discrete_log(
        Q_, P_, ord=oq, operation="other", identity=identity, inverse=inv, op=add
    )

    return Integer(dq)


def solve_dlp_over_N():
    p, q = factor()
    dp = solve_dlp_over_p(p)
    dq = solve_dlp_over_q(q)
    return crt([dp, dq], [p, q + 1])


if __name__ == "__main__":
    assert is_singular(), "Curve is not singular"
    d = solve_dlp_over_N()

    from Crypto.Util.number import long_to_bytes as l2b

    flag = l2b(int(d))
    flag = flag[: flag.index(b"}") + 1]
    assert (
        flag
        == b"TSGCTF{@l1_y0u_n3Ed_IS_ReaDiNG_5ilvErman_ThE_@r1thmetic_of_e11iPtiC_cURVe5}"
    )
    print(flag)