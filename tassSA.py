import sys
import re
import N6502
from collections import namedtuple

AddLUTTupple = namedtuple("addressLookup","address,name,size")
CodeSetTupple = namedtuple("codeSetTupple","hex,raw,full")
CallsSetTupple = namedtuple("callSetTupple","name,address,preserve")
FunctionLevelCode = namedtuple("functionLevelCode","name,address,code,trashes,modifies,errors,calls,internalTrashList")


def convertVariableLineToLookup( line, dic ):
    address = line[1:5]
    startOfSize = line.rfind(".")
    varName = line[6:startOfSize-1].strip()
    size = 1
    if line.rfind(".word") > 0:
        size = 2
    temp = AddLUTTupple(address,varName,size)
    dic[varName] = temp
 #   print( "@"+address+" "+varName+" size : " + str(size))

def getLabelFrom( string ):
    full = string
    if ";" in full: #is there a comment
        full = full.split(";")[0] # get the opcode side
    full = full[4:].strip() # remove the opcode
    if full.endswith(",x") | full.endswith(",y"):
        full = full[:-2] 
    return full    
        
def isLabelAndNotAddr( string ):
    if string.startswith("$") | string.startswith("%") | string[0].isdigit():
        return False
    return True
    
def listToString( li ):
    out = ""
    if len(li) == 0:
        return "none"
    if len(li) == 1:
        return li[0]
    index = 0
    for part in li:
        out += part
        index += 1
        if index != len(li):
            out += ", " 
    return out

    
#with open("D:\\GitHub\\SpyHunter128\\spy128_main.list") as f:
#    lines = f.read().splitlines()
with open(sys.argv[1]) as f:
    lines = f.read().splitlines()
    
stripEqualsLines = [] #empty list
variableLookup =  {} #empty dictionary
noEqualStartRE = re.compile(r"^=")
hasIF = re.compile(r"\s+(\.if|\.endif|\.else|\.include|\.for|\.next|[\s\w]+\.macro|\.endm|(\* =)|(\*=))")
isBlock = re.compile(r"[\.\d\s\w]+(\.block)")
isBend = re.compile(r"[\s]+(\.bend)")
#isVaribleDelcare = re.compile(r"^>[0-9a-f][0-9a-f][0-9a-f][0-9a-f]\s*[.\S]*\s*(\.byte|\.word).*")
isVaribleDelcare = re.compile(r"^>[0-9a-f]{4}\s*[.\S]*\s*(\.byte|\.word).*")
isComment = re.compile(r"\s+;")
isLabel = re.compile(r"^\.([0-9a-f]{4})[\t ]*([a-zA-Z0-9]+[a-zA-Z0-9_]*)$")
splitCode = re.compile(r"^\.([0-9a-f]{4})\s*([0-9a-f ]+)\s*([a-zA-Z0-9$# \,]+)\s*[+\-\w_]*?\s*([\w $%#<>+\-\*/\,\.\^;&]+$)") #1 = addr 2 = hex 3 = raw 4 = full
blockCouter = 0

for line in lines:
    if not line.strip():
        continue
    if line.startswith((";******  Return to file:",";******  Processing file:",";******  Processing input file:")):
        continue
    if blockCouter > 0:
        match = isBend.match(line)
        if match:
            blockCouter -= 1
        else:
            match = isBlock.match(line)
            if match:
                blockCouter += 1
    else:
        match = noEqualStartRE.match(line)
        if not match:
            match = hasIF.match(line)
            if not match:
                match = isBlock.match(line)
                if not match:                    
                    match = isVaribleDelcare.match(line)
                    if match:
                        convertVariableLineToLookup(line, variableLookup)
                    else:
                        stripEqualsLines.append(line)
                else:
                    blockCouter += 1

              
codeTree = {}  
currName = ""
address = ""
code = []
trashes = []
modifies = []
errors = []
calls = []
active = False 
trashA = False
trashX = False
trashY = False
otherTrashedLabels = []

for line in stripEqualsLines:
    if ";" in line:
        lineNoComment = line[0:line.find(";")].strip()
        match = isLabel.match(lineNoComment)
    else:
        match = isLabel.match(line.strip())
    if match:
        if active:
            trashesRegisters = []
            if trashA:
                trashesRegisters += ["a"]
            if trashX:
                trashesRegisters += ["x"]
            if trashY:
                trashesRegisters += ["y"]
            #then build named tupple and add it to the list
            codeTree[currName] = FunctionLevelCode(currName,address,code,trashes,modifies,errors,calls,trashesRegisters+otherTrashedLabels)
            currName = ""
            address = ""
            code = []
            trashes = []
            modifies = []
            errors = []
            calls = []
            active = False 
            trashA = False
            trashX = False
            trashY = False
            otherTrashedLabels = []      
        currName = match.group(2)
        address = match.group(1)
        active = True
       # print(match.group(1)+ "@"+match.group(2))
    else:
        if active:
            match = isComment.match(line)
            if match:
                if ";&&" in line:
                    index = line.find(";&&")
                    comment = line[index+3:].strip()    
                    if comment.startswith("trashes"):
                        vars = comment[7:].strip().split(",")
                        for thing in vars:
                            if thing not in trashes:
                                trashes.append(thing) 
                    elif comment.startswith("modifies"):
                        vars = comment[8:].strip().split(",")
                        for thing in vars:
                            if thing not in modifies:
                                modifies.append(thing)            
            else:
                match = splitCode.match(line)
                if match:
                    temphex = match.group(2)
                    parts = temphex.strip().split(" ")
                    hexNums = [];
                    for part in parts:
                        hexNums.append( int(part,16) )
                    code.append( CodeSetTupple(hexNums, match.group(3), match.group(4)))
                    #check to see if this calls things
                    if N6502.doesOpcodeBrachorJump(hexNums[0]):
                        full = getLabelFrom(match.group(4))
                        if len(full) == 0:
                            print (line)
                        if not (full.startswith("+") or full.startswith("-") or full.startswith("_")):
                            preserves = [];
                            if ";&&preserve" in match.group(4):
                                allPres = match.group(4).split(";&&preserve")
                                preserves = allPres[1].strip().split(",")
                            found = False
                            callData = CallsSetTupple(full,match.group(1),preserves);
                          #  print( currName )
                            for thing in calls:
                           #     print( "Comparing " + thing.name + " to " + full)
                                if thing.name == full:
                                    found = True 
                            if found == False:
                          #      print( "\t adding " + full)
                                calls.append(callData)
                    elif N6502.doesOpcodeTrashA(hexNums[0]):
                        trashA = True
                    elif N6502.doesOpcodeTrashX(hexNums[0]):
                        trashX = True
                    elif N6502.doesOpcodeTrashY(hexNums[0]):
                        trashY = True
                    elif N6502.doesOpcodeTrashMemory(hexNums[0]):
                        label = getLabelFrom(match.group(4))
                        if isLabelAndNotAddr(label):
                            if label not in otherTrashedLabels:
                                otherTrashedLabels.append(label)

for name,FLC in codeTree.items():
    for call in FLC.calls:
        if len(call.preserve) > 0:
            calleeFLC = codeTree[call.name]
            for var in call.preserve:
                if var in calleeFLC.trashes or var in calleeFLC.modifies:
                    print( "ERROR:" + name + ":" + call.name + " doesn't preserve " + var) 
        
with open(sys.argv[2], 'w') as out:
    out.write('<HEAD><style>table{\ntable-layout:fixed;\n}\n\ntd{\nword-wrap:break-word\n}\n</style></HEAD><BODY><table width="80%" border="1">\n')
    for index in sorted(codeTree, key=str.lower):
        FLC = codeTree[index]
        totalLen = 0
        outHex = ""
        for code in FLC.code:
            totalLen += len(code.hex)
        subFuncList = [call.name for call in FLC.calls]
        #print( FLC.name + " @ " + FLC.address + " size = " + str(totalLen) + " trashes " + str(FLC.trashes) + " calls " + str(subFuncList) + " calc trashes " + str(FLC.internalTrashList))
        out.write('<tr><td><b>Name:</b></td><td>'+FLC.name+'</td><td><b>Address:</b></td><td>$'+FLC.address+'</td><td><b>Size:</b></td><td>'+str(totalLen)+'</td></tr>')
        out.write('<tr><td><b>Calls:</b></td><td colspan="5">'+listToString(subFuncList)+'</td></tr>')
        out.write('<tr><td><b>Modifies:</b></td><td colspan="2">'+listToString(FLC.modifies)+'</td><td><b>Trashes:</b></td><td colspan="2">'+listToString(FLC.trashes)+'</td></tr>\n')
        out.write('<tr><td colspan="5">&nbsp<td/></tr>')
        if "_DONT_CARE_" not in FLC.trashes:
            error = set(FLC.internalTrashList) - set(FLC.trashes) - set(FLC.modifies)
            for er in error:
                print ( "ERORR : " + FLC.name + " Appears to trash " + er )        
            for subFunctions in subFuncList:
                if subFunctions in codeTree:
                    subFuncNames = codeTree[subFunctions]
                    if "_DONT_CARE_" not in subFuncNames.trashes:
                        missing = set(subFuncNames.internalTrashList) - set(FLC.trashes) - set(subFuncNames.modifies)
                        for miss in missing:
                                print ( FLC.name + " does not list " + miss + " in trashes and subfunction " + subFunctions + " does"  )
                else:
                    print ( subFunctions + "not found in tree" )
    out.write("</table></BODY>")
