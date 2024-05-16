import React, { Component } from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';

type MapProps = {
  latitude: number;
  longitude: number;
};

class LeafletMap extends Component<MapProps> {
  render() {
    const { latitude, longitude } = this.props;
    return (
      <MapContainer center={[latitude, longitude]} zoom={18} style={{ height: '300px', width: '100%' }}>
        <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
        <Marker position={[latitude, longitude]}>
          <Popup>A pretty CSS3 popup. Easily customizable.</Popup>
        </Marker>
      </MapContainer>
    );
  }
}

export default LeafletMap;
