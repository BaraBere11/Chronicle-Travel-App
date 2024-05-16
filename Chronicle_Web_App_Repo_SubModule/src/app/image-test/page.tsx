"use client";
import { useState, useEffect } from 'react';
import fetchImage from '../../lib/attachments';

const ImageDisplayPage = () => {
  const [imgSrc, setImgSrc] = useState('');
  const imageId = '65d3cdf0925711e1f397c8ce';

  useEffect(() => {
    fetchImage(imageId)
      .then(setImgSrc)
      .catch(() => setImgSrc(''));
  }, [imageId]);

  return (
    <div>
      {imgSrc ? (
        <img src={imgSrc} alt="Dynamic from API" style={{ maxWidth: '100%', height: 'auto' }} />
      ) : (
        <p>Image not available</p>
      )}
    </div>
  );
};

export default ImageDisplayPage;
