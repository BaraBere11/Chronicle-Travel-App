async function fetchImage(imageId: string): Promise<string> {
  console.log("fetchImage function called: entry: ", imageId);
    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/images/${imageId}`);
      if (!response.ok) {
        throw new Error('Failed to fetch image');
      }
      
      let res = await response.text();
      if (res.startsWith("https")) {
          res = res.replace("www.dropbox.com", "dl.dropboxusercontent.com").replace("?dl=0", "").replace("?dl=1", "");
      }
    return res;
    } catch (error) {
      console.error('Error fetching image:', error);
      throw error; 
    }
  }
  
  export default fetchImage;