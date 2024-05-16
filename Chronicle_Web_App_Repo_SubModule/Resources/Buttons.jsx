const ButtonSample2 = () => {
    return (
      <div className="flex min-h-screen flex-col justify-center items-center gap-9 py-8 sm:py-2 px-3 bg-gray-300">
        {/*Colors Buttons */}
        <div className="flex flex-col gap-3">
          <h2 className="text-center text-2xl font-bold">Colors Buttons</h2>
          <div className="flex justify-center sm:gap-3 gap-10 items-center flex-wrap">
            {/*Blue Button */}
            <button className="py-3 rounded bg-blue-600 hover:bg-blue-700 px-6 font-medium uppercase leading-tight text-white shadow-md transition text-xs duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/*Green Button */}
            <button className="py-3 rounded bg-green-600 hover:bg-green-700 px-6 text-xs font-medium uppercase leading-tight text-white shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/*Gray Button */}
            <button className="py-3 rounded bg-gray-600 hover:bg-gray-700 px-6 text-xs font-medium uppercase leading-tight text-white shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/*Red Button */}
            <button className="py-3 rounded bg-red-600 hover:bg-red-700 px-6 text-xs font-medium uppercase leading-tight text-white shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/*Yellow Button */}
            <button className="py-3 rounded bg-yellow-600 hover:bg-yellow-700 px-6 text-xs font-medium uppercase leading-tight text-white shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/*Black Button */}
            <button className="py-3 border-2 hover:bg-white hover:text-black hover:border-2 hover:border-[black] rounded bg-black px-6 text-xs font-medium uppercase leading-tight text-white shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
          </div>
        </div>
        {/*Outline Buttons*/}
        <div className="flex flex-col gap-3">
          <h2 className="text-center text-2xl font-bold">Outline Buttons</h2>
          <div className="flex justify-center items-center flex-wrap sm:gap-3 gap-10">
            {/*Outline Blue Button*/}
            <button className="py-3 rounded border-2 border-blue-600 bg-white px-6 text-xs font-medium uppercase leading-tight text-blue-600 hover:bg-gray-100 shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/*Outline Green Button*/}
            <button className="py-3 rounded border-2 border-green-600 bg-white px-6 text-xs font-medium uppercase leading-tight hover:bg-gray-100 text-green-600 shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/*Outline Gray Button*/}
            <button className="py-3 rounded border-2 border-gray-600 bg-white px-6 text-xs font-medium uppercase leading-tight hover:bg-gray-100 text-gray-600 shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/*Outline Red Button*/}
            <button className="py-3 rounded border-2 border-red-600 bg-white px-6 text-xs font-medium uppercase leading-tight hover:bg-gray-100 text-red-600 shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/*Outline Yellow Button*/}
            <button className="py-3 rounded border-2 border-yellow-600 bg-white px-6 text-xs font-medium uppercase leading-tight hover:bg-gray-100 text-yellow-600 shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/*Outline Black Button*/}
            <button className="py-3 rounded border-2 border-black bg-white px-6 text-xs font-medium uppercase leading-tight hover:bg-gray-100 text-black shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
          </div>
        </div>
        {/* Rounded Buttons */}
        <div className="flex flex-col gap-3">
          <h2 className="text-center text-2xl font-bold">Rounded Buttons</h2>
          <div className="flex justify-center items-center flex-wrap sm:gap-3 gap-10">
            {/* Rounded Blue Button */}
            <button className="py-3 rounded-full bg-blue-600 hover:bg-blue-700 px-6 text-xs font-medium uppercase leading-tight text-white shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/* Rounded Green Button */}
            <button className="py-3 rounded-full border-2 bg-green-600 hover:bg-green-700 px-6 text-xs font-medium uppercase leading-tight text-white shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/* Rounded Gray Button */}
            <button className="py-3 rounded-full border-2 bg-gray-600 hover:bg-gray-700 px-6 text-xs font-medium uppercase leading-tight text-white shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/* Rounded Red Button */}{" "}
            <button className="py-3 rounded-full border-2 bg-red-600 hover:bg-red-700 px-6 text-xs font-medium uppercase leading-tight text-white shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/* Rounded Yellow Button */}
            <button className="py-3 rounded-full border-2 bg-yellow-600 hover:bg-yellow-700 px-6 text-xs font-medium uppercase leading-tight text-white shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/* Rounded Black Button */}
            <button className="py-3 rounded-full border-2 bg-black px-6 text-xs hover:bg-white hover:text-black hover:border-2 hover:border-[black] font-medium uppercase leading-tight text-white shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
          </div>
        </div>
        {/* Rounded Outline Buttons */}
        <div className="flex flex-col gap-3">
          <h2 className="text-center text-2xl font-bold">
            Rounded Outline Buttons
          </h2>
          <div className="flex justify-center items-center sm:gap-3 gap-10 flex-wrap">
            {/* Rounded Outline Blue Button */}
            <button className="py-3 rounded-full border-2 border-blue-600 bg-white px-6 text-xs font-medium uppercase leading-tight text-blue-600 hover:bg-gray-100 shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/* Rounded Outline Green Button */}
            <button className="py-3 rounded-full border-2 border-green-600 bg-white px-6 text-xs font-medium uppercase hover:bg-gray-100 leading-tight text-green-600 shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/* Rounded Outline Gray Button */}
            <button className="py-3 rounded-full border-2 border-gray-600 bg-white px-6 text-xs font-medium uppercase leading-tight text-gray-600 hover:bg-gray-100 shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/* Rounded Outline Red Button */}
            <button className="py-3 rounded-full border-2 border-red-600 bg-white px-6 text-xs font-medium uppercase leading-tight text-red-600 hover:bg-gray-100 shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/* Rounded Outline Yellow Button */}
            <button className="py-3 rounded-full border-2 border-yellow-600 bg-white px-6 text-xs font-medium uppercase leading-tight hover:bg-gray-100 text-yellow-600 shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
            {/* Rounded Outline Black Button */}
            <button className="py-3 rounded-full border-2 border-black bg-white px-6 text-xs font-medium uppercase leading-tight text-black shadow-md hover:bg-gray-100 transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">
              Button
            </button>
          </div>
        </div>
      </div>
    );
  };
  export default ButtonSample2;
  