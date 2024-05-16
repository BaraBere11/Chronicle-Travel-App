import React from 'react';
import Link from 'next/link';

type Props = {
  text: string;
  link?: string;
  type?: 'button' | 'submit' | 'reset';
};

const RoundedGreenButton: React.FC<Props> = ({ text, link, type = 'button' }) => {
  const Button = (
    <button 
      type={type}
      className='py-3 rounded-3xl bg-green-500 hover:bg-green-600 px-6 text-xs font-medium uppercase leading-tight text-white shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg'
    >
      {text}
    </button>
  );

  return link ? <Link href={link}>{Button}</Link> : Button;
}

export default RoundedGreenButton;