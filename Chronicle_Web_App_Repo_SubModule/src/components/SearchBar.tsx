import React, { useState } from "react";
import { CiSearch } from "react-icons/ci";
import { IoSearchSharp } from "react-icons/io5";
import Image from 'next/image';


interface SearchBarProps {
  placeholder: string;
  onSearchChange: (text: string) => void;
}

const SearchBar: React.FC<SearchBarProps> = ({ placeholder, onSearchChange }) => {
  const [searchText, setSearchText] = useState("");

  const handleSearchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setSearchText(event.target.value);
    onSearchChange(event.target.value);
  };

  const handleClearClick = () => {
    setSearchText("");
    onSearchChange("");
  };

  return (
    <div className="flex flex-wrap items-center justify-between space-x-2 px-2">
  <a href="/home" title="link-to-home">
    <Image 
      src="/favicon.ico" 
      alt="Logo" 
      width={640} 
      height={640} 
      layout="responsive"
      className="mr-2 w-full h-full" 
    />
  </a>
  <label htmlFor="search" className="sr-only">
    Search:
  </label>
  <input
    id="search"
    type="text"
    placeholder={placeholder}
    value={searchText}
    className="border border-green-300 rounded-full py-2 px-4 focus:outline-none focus:ring focus:border-green-500"
    onChange={handleSearchChange}
    onBlur={handleClearClick}
  />
  {/* <button
    title="submit-search"
    className="bg-green-500 rounded-full py-2 px-2 text-white focus:outline-none mr-4"
    onClick={handleClearClick}
  >
    <IoSearchSharp className="text-2xl text-white"/>
  </button> */}
</div>
  );
};

export default SearchBar;
