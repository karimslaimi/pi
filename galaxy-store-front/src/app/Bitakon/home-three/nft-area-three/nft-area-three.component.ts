import { Component, OnInit } from '@angular/core';
import { NftDataService } from '../../services/nft-data/nft-data.service';

@Component({
  selector: 'app-nft-area-three',
  templateUrl: './nft-area-three.component.html',
  styleUrls: ['./nft-area-three.component.scss']
})
export class NftAreaThreeComponent implements OnInit {

  trendings : any;

  minValue: number = 0;
  maxValue: number = 100;

  constructor(private nftItems:NftDataService) {
    this.trendings = nftItems.trendingsData();
   }

  ngOnInit(): void {
  }

}
