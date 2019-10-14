import Data.Char
import System.IO

n :: Integer
n = 134896036104102133446208954973118530800743044711419303630456535295204304771800100892609593430702833309387082353959992161865438523195671760946142657809228938824313865760630832980160727407084204864544706387890655083179518455155520501821681606874346463698215916627632418223019328444607858743434475109717014763667

k :: Int
k = 131

primes :: [Integer]
primes = take k $ sieve (2 : [3, 5..])
  where
    sieve (p:xs) = p : sieve [x|x <- xs, x `mod` p > 0]

stringToInteger :: String -> Integer
stringToInteger str = foldl (\x y -> (toInteger $ ord y) + x*256) 0 str

integerToString :: Integer -> String
integerToString num = f num ""
    where
        f 0 str = str
        f num str = f (div num 256) $ (:) (chr $ fromIntegral $ num `mod` 256) str

numToBits :: Integer -> [Int]
numToBits num = f num []
    where 
        f 0 arr = arr
        f x arr = f (div x 2) ((fromInteger $ x `mod` 2) : arr)

extendBits :: Int -> [Int] -> [Int]
extendBits blockLen arr
    | len == 0 = arr
    | len > 0 = (replicate (blockLen-len) 0) ++ arr
    where len = (length arr) `mod` blockLen

calc :: Integer -> [Int] -> Integer
calc num [] = num
calc num arr = calc result restArr
    where
        num2 = num*num `mod` n
        (block, restArr) = splitAt k arr
        zipped = zipWith (\x y -> ((fromIntegral x)*y) `mod` n) block primes  
        mul = product $ filter (/=0) zipped
        result = num2*mul `mod` n

magic :: String -> String
magic input = result
    where 
        num = stringToInteger input
        bits = numToBits num
        extended = reverse $ extendBits 8 bits
        oriLen = length extended
        extendedBits = extendBits k extended
        oriLenBits = numToBits $ fromIntegral oriLen
        extendedOriLenBits = extendBits k oriLenBits
        finalBits = extendedOriLenBits ++ extendedBits
        result = show $ calc 1 (reverse finalBits)

main = do
    flag <- readFile "flag"
    putStrLn.show $ length flag
    putStrLn $ magic ("the flag is hitcon{" ++ flag ++ "}") 
