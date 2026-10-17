import os
import shutil 
sourceFolder = "."
destinationFolder = "organized"
Categories = {"Images":[ '.jpg' , '.gif' , '.png'],
              "Videos": ['.mov' , '.mp4' , '.avi'],
              "Documents":['.txt', '.pdf', '.doc'],
              "Archives":[".rar", '.zip']          
}
def getCategory(fileExt):
    for category , extentions in Categories.items():
        if fileExt.lower() in extentions:
            return category
    return "Others"
if not os.path.exists(destinationFolder):
    os.makedirs(destinationFolder)
allFiles = os.listdir(sourceFolder)
print(allFiles)
for file in allFiles:

    if os.path.isdir(os.path.join(sourceFolder,file)):
        continue

    fileExtention = (os.path.splitext(file)[1])
    
    Category = getCategory(fileExtention)
    categoryFolderPath = os.path.join(destinationFolder,Category)

    if not os.path.exists(categoryFolderPath):
        os.makedirs(categoryFolderPath)
    
    sourcePath = os.path.join(sourceFolder , file)
    destinationPath = os.path.join(categoryFolderPath,file)

    shutil.move(sourcePath , destinationPath)
    print(f"Moved {file} to {categoryFolderPath} folder")
print("organized successfully")